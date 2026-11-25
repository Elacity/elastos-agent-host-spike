//! API route handlers

use std::sync::Arc;

use axum::{
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use elastos_runtime::primitives::audit::{AuditEvent, AuditLog, TrustLevel};
use elastos_runtime::primitives::SecureTimestamp;
use serde::{Deserialize, Serialize};

use crate::resource_bridge::BridgePrincipal;
use crate::runtime::Runtime;

const SERVER_VERSION: &str = env!("ELASTOS_VERSION");

// Health check

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    version: String,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: SERVER_VERSION.into(),
    })
}

// Capsule management

#[derive(Serialize)]
pub struct CapsuleListResponse {
    capsules: Vec<CapsuleInfoResponse>,
}

#[derive(Serialize)]
pub struct CapsuleInfoResponse {
    id: String,
    name: String,
    status: String,
    /// The instance's session: the id the bridge and pending store use.
    session_id: String,
    /// Why the activation ended, once it has.
    cause: Option<String>,
    /// Plan steps whose record is unknown. Empty unless this stop resolved one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unknown_steps: Vec<String>,
}

/// Every registered activation, sorted by id. A component launch answers
/// `starting` and stays listed here as `running` until its guest ends.
pub async fn list_capsules(
    Extension(runtime): Extension<Arc<Runtime>>,
) -> Json<CapsuleListResponse> {
    let capsules = runtime
        .list_capsules()
        .await
        .into_iter()
        .map(|info| CapsuleInfoResponse {
            id: info.id,
            name: info.name,
            status: info.status,
            session_id: info.session_id,
            cause: info.cause,
            unknown_steps: Vec::new(),
        })
        .collect();

    Json(CapsuleListResponse { capsules })
}

/// Unknown fields are refused: a launch request carries no principal kind. The
/// agent kind is read only from the signed manifest at admission (F-A5-kind).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    path: String,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    launch_grant: Option<String>,
    /// A stored agent of the launch grant's person. The id is a request field,
    /// never a manifest field: the manifest decides only whether this capsule
    /// may run as an agent.
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Serialize)]
pub struct LaunchResponse {
    id: String,
    name: String,
    status: String,
    /// The instance's session: the same id, and what `GET /api/capsules`
    /// names. An agent launch's guest runs in it.
    session_id: String,
}

pub async fn launch_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(audit_log): Extension<Arc<AuditLog>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    Json(req): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
    if let Some(agent_id) = req.agent_id.as_deref() {
        if runtime.agent_is_stopping(agent_id).await {
            return Err((
                StatusCode::CONFLICT,
                crate::runtime::Runtime::AGENT_STOPPING.to_string(),
            ));
        }
    }
    let path = std::path::Path::new(&req.path);
    reject_raw_launch_principal_id(req.principal_id.as_deref())?;
    let (launcher, admission, grant_name, agent_audit) = match req.agent_id.as_deref() {
        None => {
            if crate::api::agent_plane::serves(data_dir.as_deref()) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "this runtime launches a stored agent".to_string(),
                ));
            }
            let (launcher, grant_name) = principal_from_launch_request(
                data_dir.as_deref(),
                path,
                req.principal_id,
                req.launch_grant,
            )?;
            (launcher, None, grant_name, None)
        }
        Some(agent_id) => {
            let data_dir = data_dir.as_deref().ok_or((
                StatusCode::BAD_REQUEST,
                "an agent launch needs this Home's data directory".to_string(),
            ))?;
            // The build gate runs before any folder is read, so a build
            // without agents refuses an agent launch by name.
            crate::agents::require_build()
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            // One walk names the capsule the grant must authorize and the
            // bytes this launch will run. The grant is checked against the
            // walked manifest's name, and that same value reaches admission
            // and the loader; nothing reads the folder between them.
            let walked = crate::agent_admission::walk_launch(path)
                .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            let host_cid = walked.bundle_cid.clone();
            let (launcher, launch_id, expires_at) =
                agent_launch_grant(data_dir, &walked.manifest.name, agent_id, req.launch_grant)?;
            let admission = admit_agent_launch(
                Some(data_dir),
                walked,
                Some(launcher.principal_str()),
                agent_id,
            )?;
            let audit = (
                agent_id.to_string(),
                launcher.principal_str().to_string(),
                host_cid,
                launch_id,
                expires_at,
            );
            (Some(launcher), Some(admission), None, Some(audit))
        }
    };
    // An admitted agent launch starts through the one entry that may hand the
    // bridge an agent's own id, and from the bytes admission walked. Every
    // other launch is exactly as it was.
    //
    // A component answers at admission with a `starting` entry and its
    // session. The worker changes it to `running` on `started`, and records
    // the status and cause when the guest ends.
    let started = match admission {
        Some(admission) => {
            let (agent_id, owner, host_cid, launch_id, expires_at) =
                agent_audit.as_ref().expect("agent admission has a grant");
            runtime
                .start_agent_once(
                    path,
                    admission,
                    crate::runtime::AgentStartFacts {
                        agent_id,
                        owner,
                        host_cid,
                        launch_id,
                        expires_at: *expires_at,
                        data_dir: data_dir
                            .as_deref()
                            .expect("an admitted agent launch has this Home's data directory"),
                    },
                )
                .await
        }
        None => {
            runtime
                .start_local_with_signer(path, vec![], launcher, grant_name.as_deref())
                .await
        }
    };

    match started {
        Ok((handle, signer)) => {
            let status = if handle.manifest.is_component_capsule() {
                crate::runtime::CAPSULE_STARTING
            } else {
                "launched"
            };
            let signer_did = match &signer {
                crate::runtime::Signer::Key { did } => Some(did.as_str()),
                _ => None,
            };
            if let Some((agent_id, owner, host_cid, launch_id, _)) = agent_audit {
                audit_log.emit(AuditEvent::CapsuleLaunch {
                    timestamp: SecureTimestamp::now(),
                    capsule_id: handle.id.0.clone(),
                    capsule_name: handle.manifest.name.clone(),
                    cid: Some(host_cid),
                    trust_level: TrustLevel::Untrusted,
                    signer_did: signer_did.map(String::from),
                    agent_id: Some(agent_id),
                    owner: Some(owner),
                    launch_id: Some(launch_id),
                    session_id: Some(handle.id.0.clone()),
                });
            } else {
                audit_log.capsule_launch(
                    &handle.id.0,
                    &handle.manifest.name,
                    None,
                    TrustLevel::Untrusted,
                    signer_did,
                );
            }
            Ok(Json(LaunchResponse {
                id: handle.id.0.clone(),
                name: handle.manifest.name,
                status: status.into(),
                session_id: handle.id.0,
            }))
        }
        Err(elastos_common::ElastosError::InvalidManifest(message))
            if message == crate::runtime::Runtime::AGENT_STOPPING
                || message == crate::runtime::Runtime::AGENT_ALREADY_RUNNING =>
        {
            Err((StatusCode::CONFLICT, message))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

fn agent_launch_grant(
    data_dir: &std::path::Path,
    capsule_name: &str,
    agent_id: &str,
    launch_grant: Option<String>,
) -> Result<(BridgePrincipal, String, u64), (StatusCode, String)> {
    let grant = launch_grant
        .filter(|grant| !grant.trim().is_empty())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "an agent launch needs its owner's launch grant".to_string(),
        ))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-elastos-home-token",
        HeaderValue::from_str(&grant).map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                "invalid launch_grant header value".to_string(),
            )
        })?,
    );
    super::gateway::require_internal_shell_agent_launch_grant(
        data_dir,
        &headers,
        agent_id,
        capsule_name,
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))
}

/// Admits a launch that names a stored agent. The capsule's manifest must
/// declare the agent kind, the Home must hold its own sign-in store, and the
/// named id must be the launcher's own stored agent whose key opens. Nothing
/// is started before all of that holds.
fn admit_agent_launch(
    data_dir: Option<&std::path::Path>,
    walked: crate::agent_admission::WalkedLaunch,
    launcher: Option<&str>,
    agent_id: &str,
) -> Result<crate::agent_admission::AdmissionContext, (StatusCode, String)> {
    let data_dir = data_dir.ok_or((
        StatusCode::BAD_REQUEST,
        "an agent launch needs this Home's data directory".to_string(),
    ))?;
    let sign_in_store = super::gateway::home_launch_auth_data_dir(data_dir);
    crate::agent_admission::admit_launch(data_dir, &sign_in_store, launcher, Some(agent_id), walked)
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "an agent launch needs a stored agent".to_string(),
        ))
}

fn reject_raw_launch_principal_id(principal_id: Option<&str>) -> Result<(), (StatusCode, String)> {
    if principal_id
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .is_some()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "principal_id is not launch authority; use signed launch_grant".to_string(),
        ));
    }
    Ok(())
}

/// A non-Agent launch grant names the capsule it authorizes.
fn principal_from_capsule_name(
    data_dir: Option<&std::path::Path>,
    capsule_name: &str,
    launch_grant: Option<String>,
) -> Result<Option<crate::resource_bridge::BridgePrincipal>, (StatusCode, String)> {
    let Some(grant) = launch_grant
        .map(|grant| grant.trim().to_string())
        .filter(|grant| !grant.is_empty())
    else {
        return Ok(None);
    };
    let data_dir = data_dir.ok_or((
        StatusCode::BAD_REQUEST,
        "principal launch grant unavailable".to_string(),
    ))?;
    let mut headers = HeaderMap::new();
    let header_value = HeaderValue::from_str(&grant).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid launch_grant header value".to_string(),
        )
    })?;
    headers.insert("x-elastos-home-token", header_value);
    let principal = super::gateway::require_internal_shell_launch_grant_principal(
        data_dir,
        &headers,
        &[capsule_name],
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    Ok(Some(principal))
}

type LaunchGrantBinding = (Option<BridgePrincipal>, Option<String>);

fn principal_from_launch_request(
    data_dir: Option<&std::path::Path>,
    capsule_dir: &std::path::Path,
    principal_id: Option<String>,
    launch_grant: Option<String>,
) -> Result<LaunchGrantBinding, (StatusCode, String)> {
    reject_raw_launch_principal_id(principal_id.as_deref())?;
    let launch_grant = launch_grant
        .map(|grant| grant.trim().to_string())
        .filter(|grant| !grant.is_empty());
    if launch_grant.is_some() && data_dir.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "principal launch grant unavailable".to_string(),
        ));
    }
    let capsule_name = crate::agent_admission::walk_launch(capsule_dir)
        .map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("launch_name_not_walked: {err}"),
            )
        })?
        .manifest
        .name;
    let principal = principal_from_capsule_name(data_dir, &capsule_name, launch_grant)?;
    Ok((principal, Some(capsule_name)))
}

/// The body of `DELETE /api/capsules/:id`: an optional reason (M1-R A10-R).
/// A missing body, or a body naming no reason, keeps the earlier behaviour and
/// records the reason `user`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopRequest {
    #[serde(default)]
    reason: Option<String>,
}

/// Stops a running activation. A detached agent is ended by its watcher with
/// `stopped: <reason>` as its cause, its pending requests denied by the
/// Runtime, and its entry kept for 60 s. `provider.stop` ends a guest in guest
/// code; the bridge's wait loop ends a guest inside a call.
///
/// An empty body is a stop with the reason `user`. Any other body is a
/// [`StopRequest`] or the stop is refused with `400 invalid_stop_request`,
/// and nothing is stopped. The answer is the entry as the stop left it: `200`
/// with the status and cause its one end recorded, the same answer for every
/// stop of that activation, or `202` if it has not ended within the stop's
/// wait.
pub async fn stop_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let parsed = if body.is_empty() {
        Ok(StopRequest::default())
    } else {
        serde_json::from_slice::<StopRequest>(&body)
    };
    let request = match parsed {
        Ok(request) => request,
        Err(error) => {
            let refusal =
                serde_json::json!({"error": "invalid_stop_request", "detail": error.to_string()});
            return (StatusCode::BAD_REQUEST, Json(refusal)).into_response();
        }
    };
    let reason = request
        .reason
        .map(|reason| reason.trim().to_string())
        .filter(|reason| !reason.is_empty())
        .unwrap_or_else(|| "user".to_string());
    match runtime.stop_capsule_with_reason(&id, &reason).await {
        Ok(Some(info)) => {
            // One hold of the plan lock. A live row, or an effect that can
            // still land, is stopping: the names are copied and stay in the
            // book. Stopped is said only once the row has ended and nothing
            // is in flight, and that answer is the one that removes the names.
            capsule_stop_response(
                info.id,
                info.name,
                info.status,
                info.session_id,
                info.cause,
                runtime.plan_stop_decision(&id, info.ended_at.is_some()),
            )
        }
        Ok(None) => {
            // The registry row can be gone after its retention while an
            // effect is still landing, or while a step resolved as unknown
            // after that row left. That Stop still names the outcome. A row
            // that left with nothing in the plan book is not found.
            let decision = runtime.plan_stop_decision(&id, true);
            if !decision.stopping && decision.unknown_steps.is_empty() {
                (StatusCode::NOT_FOUND, format!("Capsule {} not found", id)).into_response()
            } else {
                capsule_stop_response(
                    id.clone(),
                    id.clone(),
                    if decision.stopping {
                        "stopping".to_string()
                    } else {
                        "stopped".to_string()
                    },
                    id,
                    None,
                    decision,
                )
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to stop capsule: {}", e),
        )
            .into_response(),
    }
}

/// Body of `POST /api/capsules/stop-agent`. The agent id is the principal
/// on the Runtime rows. A settle path that must end only the session its
/// own Start made also names that `session_id`; without it every live row
/// of the agent is stopped. A capsule name is not a field: an unknown field
/// is refused and nothing is stopped.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopAgentRequest {
    agent_id: String,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Serialize)]
struct StoppedAgentBody {
    session_id: String,
    status: String,
    /// Whether this stop left `ended_at` set. The gateway's signed row says
    /// `ok` only when this is true and `status` is an ended status.
    ended: bool,
}

#[derive(Serialize)]
struct UnknownPlanStepBody {
    session_id: String,
    request_id: String,
    /// Always `unknown`. The record uses the same word. This is not done
    /// and it is not refused.
    outcome: String,
}

#[derive(Serialize)]
struct StopAgentResponse {
    stopped: Vec<StoppedAgentBody>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    stopping: Vec<StoppedAgentBody>,
    /// Steps whose record is unknown. Stop names them and does not call them
    /// done or refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unknown: Vec<UnknownPlanStepBody>,
    /// `stopped` when this call found the sessions already ended and did not
    /// stop a further row.
    #[serde(skip_serializing_if = "Option::is_none")]
    already: Option<String>,
}

fn capsule_stop_response(
    body_id: String,
    name: String,
    status_text: String,
    session_id: String,
    cause: Option<String>,
    decision: crate::runtime::PlanStopDecision,
) -> axum::response::Response {
    let status = if decision.stopping {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    let answer = CapsuleInfoResponse {
        id: body_id,
        name,
        status: if decision.stopping {
            "stopping".to_string()
        } else if !decision.unknown_steps.is_empty() {
            "stopped".to_string()
        } else {
            status_text
        },
        session_id,
        cause,
        unknown_steps: decision.unknown_steps,
    };
    (status, Json(answer)).into_response()
}

fn unknown_step_bodies(runtime: &Runtime, agent_id: &str) -> Vec<UnknownPlanStepBody> {
    runtime
        .take_unknown_plan_steps(agent_id)
        .into_iter()
        .map(|step| UnknownPlanStepBody {
            session_id: step.session_id,
            request_id: step.request_id,
            outcome: "unknown".to_string(),
        })
        .collect()
}

fn copy_unknown_step_bodies(runtime: &Runtime, agent_id: &str) -> Vec<UnknownPlanStepBody> {
    runtime
        .copy_unknown_plan_steps(agent_id)
        .into_iter()
        .map(|step| UnknownPlanStepBody {
            session_id: step.session_id,
            request_id: step.request_id,
            outcome: "unknown".to_string(),
        })
        .collect()
}

fn stopped_rows_for_unknown(unknown: &[UnknownPlanStepBody]) -> Vec<StoppedAgentBody> {
    let mut sessions: Vec<String> = unknown.iter().map(|step| step.session_id.clone()).collect();
    sessions.sort();
    sessions.dedup();
    sessions
        .into_iter()
        .map(|session_id| StoppedAgentBody {
            session_id,
            status: "stopped".to_string(),
        })
        .collect()
}

/// Stops every live row whose principal is this agent. The start record is
/// checked before the row is stopped: a missing record, or one that names
/// another agent, is refused and that row stays up. The session's one end
/// writes the one audit, with the reason of that end, and then drops the
/// record. This route does not write a second one. A row is chosen by the
/// principal. The host's capsule name is not read.
pub async fn stop_agent_session(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(_audit_log): Extension<Arc<AuditLog>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    let request = match serde_json::from_slice::<StopAgentRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            let refusal =
                serde_json::json!({"error": "invalid_stop_request", "detail": error.to_string()});
            return (StatusCode::BAD_REQUEST, Json(refusal)).into_response();
        }
    };
    let agent_id = request.agent_id;
    if agent_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "an agent stop needs an agent id".to_string(),
        )
            .into_response();
    }
    // This Stop's guard clears only its own token, including cancellation and panic.
    // Lock order, shared with retire and one live run: `begin_agent_stop`
    // takes `agent_launches`, then `stop_marks`. The live-run mutex is not
    // taken here. A Start admits `live_runs` only while it already holds
    // `agent_launches`.
    let _stop = runtime.begin_agent_stop(&agent_id).await;
    #[cfg(test)]
    {
        runtime.pause_before_stop_rows(&agent_id).await;
        if runtime.take_stop_panic_after_mark(&agent_id) {
            panic!("stop panicked after its mark");
        }
    }
    stop_collected_agent_rows(&runtime, &agent_id, request.session_id.as_deref()).await
}

/// `stopping` (202) while a plan effect of this agent can still land.
/// `stopped` is not said for that session.
fn plan_write_still_open(runtime: &Runtime, agent_id: &str) -> Option<axum::response::Response> {
    let sessions = runtime.inflight_plan_sessions(agent_id);
    // A landing effect keeps the names in the book. Only a stopped answer
    // removes them.
    let unknown = if sessions.is_empty() {
        unknown_step_bodies(runtime, agent_id)
    } else {
        copy_unknown_step_bodies(runtime, agent_id)
    };
    if sessions.is_empty() && unknown.is_empty() {
        return None;
    }
    if sessions.is_empty() {
        return Some(
            (
                StatusCode::OK,
                Json(StopAgentResponse {
                    stopped: stopped_rows_for_unknown(&unknown),
                    stopping: Vec::new(),
                    unknown,
                    already: None,
                }),
            )
                .into_response(),
        );
    }
    Some(
        (
            StatusCode::ACCEPTED,
            Json(StopAgentResponse {
                stopped: Vec::new(),
                stopping: sessions
                    .into_iter()
                    .map(|session_id| StoppedAgentBody {
                        session_id,
                        status: "stopping".to_string(),
                    })
                    .collect(),
                unknown,
                already: None,
            }),
        )
            .into_response(),
    )
}

/// Reads and stops rows after the per-agent stopping flag is set.
/// `only_session` is the settle path of a Start: keep only that row, so an
/// earlier session of the same agent, which already has its own completion
/// row, stays up. `None` stops every live row of the agent.
async fn stop_collected_agent_rows(
    runtime: &Runtime,
    agent_id: &str,
    only_session: Option<&str>,
) -> axum::response::Response {
    let mut ids = runtime.live_sessions_for_agent(agent_id).await;
    if let Some(session_id) = only_session {
        ids.retain(|id| id == session_id);
    }
    if ids.is_empty() {
        if let Some(response) = plan_write_still_open(runtime, agent_id) {
            return response;
        }
        return (
            StatusCode::NOT_FOUND,
            format!("agent {agent_id} has no running session"),
        )
            .into_response();
    }
    let mut ready = Vec::new();
    let mut refusal: Option<&'static str> = None;
    for id in &ids {
        let Some(info) = runtime.get_capsule(id).await else {
            continue;
        };
        if info.ended_at.is_some() {
            continue;
        }
        match runtime.agent_session(id).await {
            Some(record) if record.agent_id == agent_id => ready.push(id.clone()),
            Some(_) => {
                refusal = Some("agent session record names a different agent");
            }
            None => {
                refusal = Some("agent session has no start record");
            }
        }
    }
    if ready.is_empty() {
        // A 409 is this call's answer. An earlier unknown step does not
        // replace it, and this call does not take those names.
        if let Some(reason) = refusal {
            return (StatusCode::CONFLICT, reason.to_string()).into_response();
        }
        if let Some(response) = plan_write_still_open(runtime, agent_id) {
            return response;
        }
        return (
            StatusCode::OK,
            Json(StopAgentResponse {
                stopped: Vec::new(),
                stopping: Vec::new(),
                unknown: Vec::new(),
                already: Some("stopped".to_string()),
            }),
        )
            .into_response();
    }
    runtime.note_agent_stop_requested(agent_id).await;
    let mut stopped = Vec::with_capacity(ready.len());
    let mut stopping = Vec::new();
    for id in ready {
        let matches = runtime
            .agent_session(&id)
            .await
            .is_some_and(|record| record.agent_id == agent_id);
        if !matches {
            if let Some(info) = runtime.get_capsule(&id).await {
                stopped.push(StoppedAgentBody {
                    session_id: info.session_id,
                    status: info.status,
                    ended: info.ended_at.is_some(),
                });
            }
            continue;
        }
        let info = match runtime.stop_capsule_with_reason(&id, "owner").await {
            Ok(Some(info)) => info,
            Ok(None) => continue,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to stop agent session: {error}"),
                )
                    .into_response();
            }
        };
        if info.ended_at.is_none() || runtime.plan_effect_inflight(&id) {
            stopping.push(StoppedAgentBody {
                session_id: info.session_id,
                status: "stopping".to_string(),
                ended: false,
            });
        } else {
            stopped.push(StoppedAgentBody {
                session_id: info.session_id,
                status: info.status,
                ended: true,
            });
        }
    }
    // A session whose row already ended is absent from the live list, and its
    // effect can still be landing. Name that session here. The answer is 202
    // while any such effect remains.
    for session_id in runtime.inflight_plan_sessions(agent_id) {
        if stopping.iter().any(|row| row.session_id == session_id) {
            continue;
        }
        if let Some(pos) = stopped.iter().position(|row| row.session_id == session_id) {
            stopped.remove(pos);
        }
        stopping.push(StoppedAgentBody {
            session_id,
            status: "stopping".to_string(),
        });
    }
    // A session named in stopping is not also named in stopped.
    stopped.retain(|row| {
        !stopping
            .iter()
            .any(|stopping_row| stopping_row.session_id == row.session_id)
    });
    // While anything is still stopping, the names stay in the book for the
    // Stop that later says stopped.
    let unknown = if stopping.is_empty() {
        unknown_step_bodies(runtime, agent_id)
    } else {
        copy_unknown_step_bodies(runtime, agent_id)
    };
    if stopped.is_empty() && stopping.is_empty() {
        stopped = stopped_rows_for_unknown(&unknown);
    }
    let already = (stopped.is_empty() && stopping.is_empty() && unknown.is_empty())
        .then(|| "stopped".to_string());
    let status = if stopping.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    (
        status,
        Json(StopAgentResponse {
            stopped,
            stopping,
            unknown,
            already,
        }),
    )
        .into_response()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::gateway;
    use std::future::Future;

    pub(crate) fn make_admin(data_dir: &std::path::Path, principal_id: &str) {
        let mut state = crate::auth::load_auth_state(data_dir).unwrap();
        for principal in &mut state.principals {
            if principal.principal_id == principal_id {
                principal.role = crate::auth::RuntimePrincipalRole::Admin;
            }
        }
        crate::auth::save_auth_state(data_dir, &state, None).unwrap();
    }

    fn write_test_capsule(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let capsule_dir = dir.join(name);
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::json!({
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": name,
                "role": "app",
                "type": "wasm",
                "entrypoint": "main.wasm"
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(capsule_dir.join("main.wasm"), b"entrypoint").unwrap();
        capsule_dir
    }

    /// A5-S2b forged-kind row: a request naming an agent kind is refused.
    #[test]
    fn launch_request_carrying_an_agent_kind_is_refused() {
        let grant = serde_json::json!({"path": "/capsules/chat-wasm", "launch_grant": "t"});
        assert!(serde_json::from_value::<LaunchRequest>(grant.clone()).is_ok());
        for (field, forged) in [
            ("agent", serde_json::json!({"kind": "agent"})),
            ("kind", serde_json::json!("agent")),
            ("principal_kind", serde_json::json!("Agent")),
        ] {
            let mut request = grant.clone();
            request[field] = forged;
            assert!(serde_json::from_value::<LaunchRequest>(request).is_err());
        }
    }

    #[test]
    fn launch_without_grant_stays_principal_less_and_keeps_walked_name() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");

        let principal =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, None).unwrap();

        assert_eq!(principal, (None, Some("chat-wasm".to_string())));
    }

    #[test]
    fn launch_principal_id_rejects_raw_values() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        for value in [
            "person:local:abc",
            "person/local/abc",
            "person\\local\\abc",
            "person..local",
            "person\nlocal",
        ] {
            let err = principal_from_launch_request(
                Some(dir.path()),
                &capsule_dir,
                Some(value.to_string()),
                None,
            )
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert!(err.1.contains("not launch authority"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn principal_launch_rejects_raw_principal_id_even_with_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let err = principal_from_launch_request(
            Some(dir.path()),
            &capsule_dir,
            Some("person:local:alice".to_string()),
            Some(grant),
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("not launch authority"));
    }

    #[cfg(unix)]
    #[test]
    fn principal_launch_accepts_home_launch_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::bind_device_session_grant(dir.path(), &["chat-wasm"]).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let (principal, name) =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, Some(grant))
                .unwrap();
        assert_eq!(name.as_deref(), Some("chat-wasm"));

        assert_eq!(
            principal
                .as_ref()
                .map(crate::resource_bridge::BridgePrincipal::principal_str),
            Some(context.principal_id())
        );
    }

    #[cfg(unix)]
    #[test]
    fn principal_launch_rejects_grant_without_runtime_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let err = principal_from_launch_request(None, &capsule_dir, None, Some(grant)).unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "principal launch grant unavailable");
    }

    #[cfg(unix)]
    #[test]
    fn principal_launch_rejects_wrong_app_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::bind_device_session_grant(dir.path(), &["system"]).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "system", &context).unwrap();

        let err = principal_from_launch_request(Some(dir.path()), &capsule_dir, None, Some(grant))
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("not authorized"));
    }

    /// `POST /api/capsules` with a launch grant, for a pinned manifest: the
    /// handler's own manifest parse refuses it, before the grant is looked at.
    #[test]
    fn a_launch_with_a_grant_stops_at_its_manifest_parse_for_a_pinned_requirement() {
        use crate::runtime::tests::{write_fixture_capsule, PINNED_MANIFEST};
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_fixture_capsule(dir.path(), PINNED_MANIFEST);
        let grant = Some("any-grant".to_string());
        let err =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, grant).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        let expected =
            "launch_name_not_walked: parse the launching capsule's manifest: unknown field `cid`";
        assert!(err.1.starts_with(expected), "{}", err.1);
    }

    /// A grantless folder still walks before launch. The pinned manifest is
    /// refused at that walk, so the launch entry is never reached.
    #[tokio::test]
    async fn a_launch_without_a_grant_stops_at_the_walk_for_a_pinned_requirement() {
        use crate::runtime::tests::{test_runtime, write_fixture_capsule, PINNED_MANIFEST};
        let (runtime, temp) = test_runtime().await;
        runtime
            .configure_capsule_admission(temp.path(), &[], true)
            .await
            .unwrap();
        let capsule_dir = write_fixture_capsule(temp.path(), PINNED_MANIFEST);
        let audit_log = std::sync::Arc::new(AuditLog::new());
        let response = launch_capsule(
            Extension(std::sync::Arc::new(runtime)),
            Extension(audit_log.clone()),
            Extension(None::<std::path::PathBuf>),
            Json(LaunchRequest {
                path: capsule_dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: None,
                agent_id: None,
            }),
        )
        .await;
        let Err((status, message)) = response else {
            panic!("a pinned manifest was launched");
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let expected =
            "launch_name_not_walked: parse the launching capsule's manifest: unknown field `cid`";
        assert!(message.starts_with(expected), "{message}");
        assert!(audit_log.recent_events(2).is_empty());
    }

    /// S1: the audit for the real instance handle names the verified signer.
    #[tokio::test]
    async fn launch_audit_names_the_verified_signer_on_the_instance_handle() {
        use crate::runtime::tests::test_runtime;
        use elastos_runtime::primitives::audit::AuditEvent;
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};

        let (runtime, temp) = test_runtime().await;
        let runtime = std::sync::Arc::new(runtime);
        let key = SigningKey::from_bytes(&[0x44; 32]);
        runtime
            .configure_capsule_admission(
                temp.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp.path().join("signed-app");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        let entrypoint = b"microvm image";
        std::fs::write(capsule_dir.join("rootfs.ext4"), entrypoint).unwrap();
        let mut manifest: elastos_common::CapsuleManifest = serde_json::from_str(
            r#"{"schema":"elastos.capsule/v1","version":"0.1.0","name":"signed-app","role":"app","type":"microvm","entrypoint":"rootfs.ext4"}"#,
        )
        .unwrap();
        sign_capsule(&key, &mut manifest, &hash_content(entrypoint)).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let audit_log = std::sync::Arc::new(AuditLog::new());
        let response = launch_capsule(
            Extension(runtime),
            Extension(audit_log.clone()),
            Extension(None::<std::path::PathBuf>),
            Json(LaunchRequest {
                path: capsule_dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: None,
                agent_id: None,
            }),
        )
        .await
        .unwrap()
        .0;

        let mut events = audit_log.recent_events(2);
        assert_eq!(events.len(), 1, "one capsule_launch event");
        let AuditEvent::CapsuleLaunch {
            capsule_id,
            signer_did,
            cid,
            ..
        } = events.remove(0)
        else {
            unreachable!("the launch emits a capsule_launch event")
        };
        assert_eq!(
            capsule_id, response.id,
            "the audit names the real instance handle"
        );
        assert_eq!(
            signer_did.as_deref(),
            Some("did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7"),
            "the audit names the verified signer"
        );
        assert_eq!(cid, None, "S1 records no CID");
    }

    /// S5 row R6.1: a forged kind is refused through `POST /api/capsules`
    /// before the launch entry, and nothing is minted. The control is the same
    /// body without a kind, launched for real, so the refusals cannot pass
    /// because the route refuses everything. Every violated check is reported
    /// in one run, so a plant shows all of them.
    #[tokio::test]
    async fn a_forged_kind_is_refused_through_the_launch_route_and_mints_nothing() {
        use crate::runtime::tests::test_runtime;
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::post;
        use elastos_runtime::primitives::audit::AuditEvent;
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
        use tower::ServiceExt;

        let (runtime, temp) = test_runtime().await;
        let runtime = Arc::new(runtime);
        let key = SigningKey::from_bytes(&[0x44; 32]);
        runtime
            .configure_capsule_admission(
                temp.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp.path().join("signed-app");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        let entrypoint = b"microvm image";
        std::fs::write(capsule_dir.join("rootfs.ext4"), entrypoint).unwrap();
        let mut manifest: elastos_common::CapsuleManifest = serde_json::from_str(
            r#"{"schema":"elastos.capsule/v1","version":"0.1.0","name":"signed-app","role":"app","type":"microvm","entrypoint":"rootfs.ext4"}"#,
        )
        .unwrap();
        sign_capsule(&key, &mut manifest, &hash_content(entrypoint)).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();

        let audit_log = Arc::new(AuditLog::new());
        // The shell-only and auth layers sit in `api/server.rs:476-496`; this
        // mount carries the handler's own three extensions.
        let app = axum::Router::new()
            .route("/api/capsules", post(launch_capsule))
            .layer(Extension(Some(temp.path().to_path_buf())))
            .layer(Extension(audit_log.clone()))
            .layer(Extension(runtime.clone()));
        let path = capsule_dir.to_string_lossy().into_owned();
        let send = |body: serde_json::Value| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        Request::builder()
                            .method("POST")
                            .uri("/api/capsules")
                            .header("content-type", "application/json")
                            .body(Body::from(body.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                (status, String::from_utf8(bytes.to_vec()).unwrap())
            }
        };

        // Three forged shapes, each refused by the request's own field set.
        let mut forged = Vec::new();
        for (field, value) in [
            ("kind", serde_json::json!("agent")),
            ("agent", serde_json::json!({"kind": "agent"})),
            ("principal_kind", serde_json::json!("Agent")),
        ] {
            let mut body = serde_json::json!({ "path": path.clone() });
            body[field] = value;
            let (status, text) = send(body).await;
            let named = text.contains(&format!("unknown field `{field}`"));
            forged.push((field, status, named));
        }
        let refused = forged
            .iter()
            .all(|(_, status, named)| *status == StatusCode::UNPROCESSABLE_ENTITY && *named);
        let minted = audit_log.recent_events(4);
        let started = runtime.list_capsules().await;
        let mut failures = Vec::new();
        if !refused {
            failures.push(format!(
                "a body carrying `kind` is refused before the launch entry: {forged:?}"
            ));
        }
        if !minted.is_empty() {
            failures.push(format!(
                "no launch was minted from a forged body: {minted:?}"
            ));
        }
        if !started.is_empty() {
            failures.push(format!(
                "no capsule started from a forged body: {started:?}"
            ));
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));

        // The control: the same body without a forged field really launches.
        let (status, text) = send(serde_json::json!({ "path": path })).await;
        assert_eq!(status, StatusCode::OK, "the control body launches: {text}");
        let control: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            control["status"], "launched",
            "the control names its status"
        );
        let id = control["id"].as_str().unwrap_or_default();
        assert!(!id.is_empty(), "the control names its instance id");
        let events = audit_log.recent_events(4);
        assert_eq!(
            events.len(),
            1,
            "the control emits one launch event: {events:?}"
        );
        let AuditEvent::CapsuleLaunch { capsule_id, .. } = &events[0] else {
            unreachable!("the control launch emits a capsule_launch event")
        };
        assert_eq!(
            capsule_id, id,
            "the one launch event names the launched instance"
        );
    }

    /// A localhost double: it records every raw request the bridge routes to
    /// the `localhost` scheme and answers `ok`. Own-root reads and writes take
    /// the protected path and never reach it, so its record shows exactly
    /// which calls fell past that path.
    #[derive(Default)]
    pub(crate) struct CapturingLocalhostProvider {
        requests: std::sync::Mutex<Vec<serde_json::Value>>,
    }

    impl CapturingLocalhostProvider {
        #[cfg(unix)]
        pub(crate) fn requests(&self) -> Vec<serde_json::Value> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl elastos_runtime::provider::Provider for CapturingLocalhostProvider {
        async fn handle(
            &self,
            _request: elastos_runtime::provider::ResourceRequest,
        ) -> Result<
            elastos_runtime::provider::ResourceResponse,
            elastos_runtime::provider::ProviderError,
        > {
            Err(elastos_runtime::provider::ProviderError::Provider(
                "raw provider fixture does not implement ResourceRequest".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            vec!["localhost"]
        }

        fn name(&self) -> &'static str {
            "capturing-localhost"
        }

        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
            self.requests.lock().unwrap().push(request.clone());
            Ok(serde_json::json!({
                "status": "ok",
                "data": {
                    "ok": true
                }
            }))
        }
    }

    /// Records every raw request the bridge routes to the model provider.
    /// When `watch` is set, each call also records the ceilings the Runtime
    /// map holds at that moment.
    #[derive(Default)]
    #[cfg(unix)]
    struct CapturingModelProvider {
        requests: std::sync::Mutex<Vec<serde_json::Value>>,
        ceilings_at_call: std::sync::Mutex<Vec<Vec<(String, u64)>>>,
        runtime: std::sync::Mutex<Option<Arc<Runtime>>>,
        revision: std::sync::Mutex<Option<String>>,
        reject_next_valid_create: std::sync::Mutex<bool>,
    }

    #[cfg(unix)]
    impl CapturingModelProvider {
        fn requests(&self) -> Vec<serde_json::Value> {
            self.requests.lock().unwrap().clone()
        }

        fn watch(&self, runtime: Arc<Runtime>) {
            *self.runtime.lock().unwrap() = Some(runtime);
        }

        fn raise_revision_after_rejection(&self) {
            *self.reject_next_valid_create.lock().unwrap() = true;
        }

        fn ceilings_at_call(&self) -> Vec<Vec<(String, u64)>> {
            self.ceilings_at_call.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    #[cfg(unix)]
    impl elastos_runtime::provider::Provider for CapturingModelProvider {
        async fn handle(
            &self,
            _request: elastos_runtime::provider::ResourceRequest,
        ) -> Result<
            elastos_runtime::provider::ResourceResponse,
            elastos_runtime::provider::ProviderError,
        > {
            Err(elastos_runtime::provider::ProviderError::Provider(
                "raw provider fixture does not implement ResourceRequest".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            vec!["model"]
        }

        fn name(&self) -> &'static str {
            "capturing-model"
        }

        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
            let runtime = self.runtime.lock().unwrap().clone();
            if let Some(runtime) = runtime {
                let held = runtime.model_token_ceilings_held();
                self.ceilings_at_call.lock().unwrap().push(held);
            }
            self.requests.lock().unwrap().push(request.clone());
            if request["op"] == "offers_list" {
                let revision = self
                    .revision
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| "sha256:fixture".into());
                return Ok(serde_json::json!({
                    "status": "ok", "data": {
                        "offers": [{
                            "id": "offer:fixture", "operation": "text.generate",
                            "policy": {"input_bytes_limit": 100, "inline_output_bytes_limit": 64}
                        }, {
                            "id": "offer:large", "operation": "text.generate",
                            "policy": {"input_bytes_limit": 300, "inline_output_bytes_limit": 64}
                        }],
                        "offer_revisions": {"offer:fixture": revision, "offer:large": "sha256:large"}
                    }
                }));
            }
            if request["operation"] != "text.generate" {
                return Err(elastos_runtime::provider::ProviderError::Provider(
                    "requested operation does not match configured offer".into(),
                ));
            }
            let reject_valid_create = {
                let mut reject = self.reject_next_valid_create.lock().unwrap();
                std::mem::take(&mut *reject)
            };
            if reject_valid_create {
                *self.revision.lock().unwrap() = Some("sha256:raised".into());
                return Err(elastos_runtime::provider::ProviderError::Provider(
                    "fixture rejects first valid create".into(),
                ));
            }
            let binding: elastos_model_contract::RuntimeCreateBinding =
                serde_json::from_value(request["runtime_binding"].clone())
                    .expect("the Runtime stamps every model create");
            let answer = request["input"]["prompt"].as_str().unwrap_or_default();
            Ok(serde_json::json!({
                "status": "ok",
                "data": {
                    "schema": "elastos.model.run/v1",
                    "run_id": elastos_model_contract::model_run_id(&binding),
                    "offer_id": request["offer_id"],
                    "operation": request["operation"],
                    "status": "completed",
                    "sequence_cursor": 1,
                    "terminal": {"status": "completed", "output": {"text": answer}},
                }
            }))
        }
    }

    /// A Home whose stored agents are the probe package: the probe's manifest
    /// name and the CID its capsule directory records, signed by a key the
    /// runtime trusts. Two agents, or as many as asked for, share the Home.
    pub(crate) struct ProbeLaunch {
        /// The fixture's own folders. `None` when the probe shares a Home
        /// that another fixture owns; its folders then live under that Home.
        _temp: Option<tempfile::TempDir>,
        fixture_root: std::path::PathBuf,
        pub(crate) data_dir: std::path::PathBuf,
        runtime: Arc<Runtime>,
        audit_log: Arc<AuditLog>,
        pub(crate) pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
        /// The same token store the manager holds: the live view's own input.
        capability_store: Arc<elastos_runtime::capability::CapabilityStore>,
        /// The provider registry the bridge dispatches through, so a row can
        /// make a late call under the context the end left.
        registry: Arc<elastos_runtime::provider::ProviderRegistry>,
        provider: Arc<CapturingLocalhostProvider>,
        capsule_dir: std::path::PathBuf,
        context: gateway::HomeLaunchTokenContext,
        pub(crate) agents: Vec<String>,
        /// The stored person every agent here belongs to. It is the person
        /// `agents::create` records in each agent's `owner`.
        owner: String,
        /// Where the revoke list is saved, for a probe that saves it.
        tokens: Option<std::path::PathBuf>,
    }

    /// The probe's token plane: an unsaved store under a fresh key, or `store`
    /// under the fixed key a restarted plane is made with again.
    #[cfg(unix)]
    fn probe_token_manager(
        store: Option<elastos_runtime::capability::CapabilityStore>,
        audit_log: Arc<AuditLog>,
    ) -> elastos_runtime::capability::CapabilityManager {
        probe_token_plane(store, audit_log).1
    }

    /// [`probe_token_manager`], and the same store the manager holds, so a
    /// row's shell view reads exactly the grants the manager minted.
    fn probe_token_plane(
        store: Option<elastos_runtime::capability::CapabilityStore>,
        audit_log: Arc<AuditLog>,
    ) -> (
        Arc<elastos_runtime::capability::CapabilityStore>,
        elastos_runtime::capability::CapabilityManager,
    ) {
        use elastos_runtime::capability::{CapabilityManager, CapabilityStore};
        use elastos_runtime::primitives::metrics::MetricsManager;
        let metrics = Arc::new(MetricsManager::new());
        match store {
            None => {
                let store = Arc::new(CapabilityStore::new());
                let manager = CapabilityManager::new(store.clone(), audit_log, metrics);
                (store, manager)
            }
            Some(store) => {
                let store = Arc::new(store);
                let manager = CapabilityManager::with_key(
                    elastos_runtime::signature::SigningKey::from_bytes(&[0x52; 32]),
                    store.clone(),
                    audit_log,
                    metrics,
                );
                (store, manager)
            }
        }
    }

    const PROBE_HOST: &str = "a5-launch-probe";
    /// The resource of the requests a row seeds in an instance's session:
    /// one granted, one pending. A grant loop holds it, so the pending one
    /// stays pending until the instance's end.
    #[cfg(unix)]
    const SEEDED_REQUEST_RESOURCE: &str = "elastos://content/publish";
    /// The package CID the install records; the launch compares the Runtime's own walk.
    const PROBE_REGISTRY_CID: &str = "bafkreia5probe";

    /// An Agent Host of the probe's world that asks the bridge for nothing and
    /// spins in `run`. The mid-compute stop row needs a guest in guest code,
    /// where only the epoch callback can end it.
    #[cfg(unix)]
    const SPIN_COMPONENT: &str = r#"(component
      (import "elastos:bus/types@1.0.0" (instance $types
        (type $error (variant
          (case "denied" string) (case "not-found" string) (case "invalid" string)
          (case "unavailable" string) (case "timeout" string) (case "internal" string)))
        (export "bus-error" (type (eq $error)))))
      (alias export $types "bus-error" (type $bus-error))
      (core module $m
        (memory (export "memory") 1)
        ;; A loop-carried division: each iteration's fuel buys a division's
        ;; latency, so the spinner keeps computing long enough for a stop
        ;; request (with the flag ignored, it ends when its fuel does).
        (func $spin (local $x f64)
          (local.set $x (f64.const 1.0000001))
          (loop $again
            (local.set $x (f64.div (local.get $x) (f64.const 1.0000001)))
            (local.set $x (f64.mul (local.get $x) (f64.const 1.0000001)))
            (br $again)))
        (func (export "run") (result i32) (call $spin) (i32.const 0)))
      (core instance $i (instantiate $m))
      (func $run (result (result (error $bus-error)))
        (canon lift (core func $i "run") (memory $i "memory")))
      (instance $lifecycle (export "run" (func $run)))
      (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#;

    /// The same world, but the guest spins in its start function, so it is
    /// in guest code while the registry still says `starting`. Each turn asks
    /// the runtime for the memory's size, which makes its fuel last about a
    /// second: left alone, the start ends on its own fuel, `failed`.
    #[cfg(unix)]
    const SPIN_START_COMPONENT: &str = r#"(component
      (import "elastos:bus/types@1.0.0" (instance $types
        (type $error (variant
          (case "denied" string) (case "not-found" string) (case "invalid" string)
          (case "unavailable" string) (case "timeout" string) (case "internal" string)))
        (export "bus-error" (type (eq $error)))))
      (alias export $types "bus-error" (type $bus-error))
      (core module $m
        (memory (export "memory") 1)
        (func $spin
          (loop $again
            (drop (memory.grow (i32.const 0)))
            (br $again)))
        (start $spin)
        (func (export "run") (result i32) (i32.const 0)))
      (core instance $i (instantiate $m))
      (func $run (result (result (error $bus-error)))
        (canon lift (core func $i "run") (memory $i "memory")))
      (instance $lifecycle (export "run" (func $run)))
      (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#;

    /// The same world, but `run` executes `unreachable`. The activation ends
    /// `failed` with the trap, and the live-run token is released.
    #[cfg(unix)]
    const CRASH_COMPONENT: &str = r#"(component
      (import "elastos:bus/types@1.0.0" (instance $types
        (type $error (variant
          (case "denied" string) (case "not-found" string) (case "invalid" string)
          (case "unavailable" string) (case "timeout" string) (case "internal" string)))
        (export "bus-error" (type (eq $error)))))
      (alias export $types "bus-error" (type $bus-error))
      (core module $m
        (memory (export "memory") 1)
        (func (export "run") (result i32) unreachable))
      (core instance $i (instantiate $m))
      (func $run (result (result (error $bus-error)))
        (canon lift (core func $i "run") (memory $i "memory")))
      (instance $lifecycle (export "run" (func $run)))
      (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#;

    impl ProbeLaunch {
        pub(crate) async fn new(names: &[&str]) -> Self {
            Self::new_with(tempfile::tempdir().unwrap(), names, None).await
        }

        async fn new_with(
            temp: tempfile::TempDir,
            names: &[&str],
            tokens: Option<elastos_runtime::capability::CapabilityStore>,
        ) -> Self {
            let data_dir = temp.path().join("data");
            std::fs::create_dir_all(&data_dir).unwrap();
            let context = gateway::bind_device_session_grant(
                &data_dir,
                &[gateway::HOME_CAPSULE_ID, PROBE_HOST],
            )
            .unwrap();
            let owner = context.principal_id().to_string();
            crate::auth::store_test_principal_root_protection(&data_dir, &owner);
            make_admin(&data_dir, &owner);
            let record = crate::auth::stored_principal_record(&data_dir, &owner)
                .unwrap()
                .unwrap();
            Self::build(
                Some(temp),
                data_dir,
                &owner,
                &record.proof_binding_id,
                "session:a5-launch",
                &context,
                names,
                tokens,
            )
            .await
        }

        /// A probe whose capability store is opened in its Home's data
        /// folder as a Home's start opens it, at [`Self::tokens_dir`], and
        /// whose tokens are signed with a fixed key, so
        /// [`Self::restarted_tokens`] is this Home's token plane after a
        /// restart.
        #[cfg(unix)]
        pub(crate) async fn with_saved_revokes(names: &[&str]) -> Self {
            use crate::api::handlers::settle;
            let temp = tempfile::tempdir().unwrap();
            let data_dir = temp.path().join("data");
            let store = settle::open_capability_store(&data_dir).await.unwrap();
            let mut probe = Self::new_with(temp, names, Some(store)).await;
            probe.tokens = Some(settle::capability_store_dir(&data_dir));
            probe
        }

        #[cfg(unix)]
        pub(crate) fn tokens_dir(&self) -> std::path::PathBuf {
            self.tokens.clone().expect("a probe with saved revokes")
        }

        /// A new token plane over this Home's capability store, opened as
        /// its start opens it, and the same key.
        #[cfg(unix)]
        pub(crate) async fn restarted_tokens(
            &self,
        ) -> elastos_runtime::capability::CapabilityManager {
            let store = crate::api::handlers::settle::open_capability_store(&self.data_dir)
                .await
                .unwrap();
            probe_token_manager(Some(store), self.audit_log.clone())
        }

        /// A new token plane over the saved store alone, without the pending
        /// revocation list, and the same key.
        #[cfg(unix)]
        pub(crate) async fn saved_store_tokens(
            &self,
        ) -> elastos_runtime::capability::CapabilityManager {
            let store =
                elastos_runtime::capability::CapabilityStore::with_persistence(self.tokens_dir())
                    .await
                    .unwrap();
            probe_token_manager(Some(store), self.audit_log.clone())
        }

        /// A probe over an existing Home. The stored agents belong to
        /// `owner`, a person of that Home, and the launch grant is issued from
        /// that person's sign-in context. A launch from this probe reads and
        /// writes the same data directory the gateway routes use.
        pub(in crate::api) async fn over_home(
            data_dir: std::path::PathBuf,
            owner: &str,
            proof_binding_id: &str,
            session_id: &str,
            context: &gateway::HomeLaunchTokenContext,
            names: &[&str],
        ) -> Self {
            Self::build(
                None,
                data_dir,
                owner,
                proof_binding_id,
                session_id,
                context,
                names,
                None,
            )
            .await
        }

        #[allow(clippy::too_many_arguments)]
        async fn build(
            temp: Option<tempfile::TempDir>,
            data_dir: std::path::PathBuf,
            owner: &str,
            proof_binding_id: &str,
            session_id: &str,
            context: &gateway::HomeLaunchTokenContext,
            names: &[&str],
            tokens: Option<elastos_runtime::capability::CapabilityStore>,
        ) -> Self {
            use crate::agents;
            use elastos_compute::providers::ComponentProvider;
            use elastos_runtime::provider::ProviderRegistry;
            use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
            use elastos_storage::providers::LocalFSProvider;

            let fixture_root = temp
                .as_ref()
                .map(|temp| temp.path().to_path_buf())
                .unwrap_or_else(|| data_dir.join(".s5-probe"));
            let storage = Arc::new(
                LocalFSProvider::new(fixture_root.join("storage"))
                    .await
                    .unwrap(),
            );
            let runtime = Arc::new(Runtime::with_providers_and_component(
                storage,
                Vec::new(),
                Some(Arc::new(ComponentProvider::new())),
            ));
            let key = SigningKey::from_bytes(&[0x44; 32]);
            runtime
                .configure_capsule_admission(
                    &data_dir,
                    &[hex::encode(key.verifying_key().to_bytes())],
                    false,
                )
                .await
                .unwrap();
            let audit_log = Arc::new(AuditLog::new());
            let (capability_store, capability_manager) =
                probe_token_plane(tokens, audit_log.clone());
            let capability_manager = Arc::new(capability_manager);
            let pending_store = Arc::new(
                elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
            );
            let provider = Arc::new(CapturingLocalhostProvider::default());
            let registry = Arc::new(ProviderRegistry::new());
            registry.register(provider.clone()).await;
            runtime
                .set_provider_registry(
                    registry.clone(),
                    capability_manager.clone(),
                    pending_store.clone(),
                    data_dir.clone(),
                )
                .await;

            let caller = agents::Caller {
                principal_id: owner,
                proof_binding_id,
                session_id,
            };
            agents::set_enabled(&data_dir, &caller, true, 1).unwrap();

            let capsule_dir = fixture_root.join(PROBE_HOST);
            std::fs::create_dir_all(&capsule_dir).unwrap();
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/a5-launch-probe");
            for file in ["capsule.json", "a5-launch-probe.component.wasm"] {
                std::fs::copy(fixture.join(file), capsule_dir.join(file)).unwrap();
            }
            std::fs::write(
                capsule_dir.join(".elastos-cid"),
                format!("{PROBE_REGISTRY_CID}\n"),
            )
            .unwrap();
            let wasm = std::fs::read(capsule_dir.join("a5-launch-probe.component.wasm")).unwrap();
            let mut manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(capsule_dir.join("capsule.json")).unwrap())
                    .unwrap();
            assert_eq!(
                manifest.agent,
                Some(elastos_common::AgentDeclaration {
                    kind: elastos_common::AgentKind::Agent
                }),
                "the manifest declares the agent kind and names no id of its own"
            );
            sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
            std::fs::write(
                capsule_dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            // The bytes are final: the folder the probe starts is the one an
            // install recorded here, and the stored host CID is the one walk
            // the Runtime makes of exactly these files.
            crate::setup::record_install_cid(&data_dir, &capsule_dir, &capsule_dir);
            let probe_cid = crate::stage_cmd::bundle_cid(&capsule_dir)
                .expect("the probe host bundle is walkable");
            let agents = names
                .iter()
                .map(|name| {
                    agents::create(
                        &data_dir,
                        &caller,
                        &agents::CreateRequest {
                            display_name: name.to_string(),
                            agent_host: PROBE_HOST.to_string(),
                            request_id: format!("request-{name}"),
                        },
                        |host| {
                            Ok(
                                crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                                    host,
                                    PROBE_REGISTRY_CID,
                                    &probe_cid,
                                ),
                            )
                        },
                        1,
                    )
                    .unwrap()
                    .agent_id
                })
                .collect::<Vec<String>>();
            for id in &agents {
                agents::set_active(&data_dir, &caller, id, true, 1).unwrap();
            }
            Self {
                _temp: temp,
                fixture_root,
                data_dir,
                runtime,
                audit_log,
                pending_store,
                capability_manager,
                capability_store,
                registry,
                provider,
                capsule_dir,
                context: context.clone(),
                agents,
                owner: owner.to_string(),
                tokens: None,
            }
        }

        /// Writes a second signed Agent Host folder whose manifest adds
        /// `claims` to its capabilities, exactly as the stored host is
        /// written, and returns the folder and the CID the Runtime's walk
        /// gives it. The extra claims name another agent's root; admission
        /// still binds the agent the request names.
        #[cfg(unix)]
        fn host_with_claims(&self, name: &str, claims: &[String]) -> (std::path::PathBuf, String) {
            use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};

            let key = SigningKey::from_bytes(&[0x44; 32]);
            let dir = self.fixture_root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/a5-launch-probe");
            for file in ["capsule.json", "a5-launch-probe.component.wasm"] {
                std::fs::copy(fixture.join(file), dir.join(file)).unwrap();
            }
            let wasm = std::fs::read(dir.join("a5-launch-probe.component.wasm")).unwrap();
            let mut manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap();
            manifest.capabilities.extend_from_slice(claims);
            sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let cid = crate::stage_cmd::bundle_cid(&dir).expect("the claimed host is walkable");
            (dir, cid)
        }

        /// A signed copy of the probe whose manifest asks for `tokens` model
        /// tokens (`None` asks for none) and may call the model.
        #[cfg(unix)]
        fn model_host(&self, name: &str, tokens: Option<u64>) -> (std::path::PathBuf, String) {
            use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
            let key = SigningKey::from_bytes(&[0x44; 32]);
            let dir = self.fixture_root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/a5-launch-probe");
            for file in ["capsule.json", "a5-launch-probe.component.wasm"] {
                std::fs::copy(fixture.join(file), dir.join(file)).unwrap();
            }
            let wasm = std::fs::read(dir.join("a5-launch-probe.component.wasm")).unwrap();
            let mut manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap();
            manifest.capabilities.push("elastos://model/*".to_string());
            manifest.resources.model_tokens = tokens;
            sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let cid = crate::stage_cmd::bundle_cid(&dir).expect("the model host is walkable");
            (dir, cid)
        }

        /// Creates one more agent of this Home's owner, bound to `host_dir`
        /// and to `host_cid` as its stored Agent Host.
        #[cfg(unix)]
        fn create_agent_for_host(&self, name: &str, host_cid: &str) -> String {
            use crate::agents;
            let record = crate::auth::stored_principal_record(&self.data_dir, &self.owner)
                .unwrap()
                .unwrap();
            let caller = agents::Caller {
                principal_id: &self.owner,
                proof_binding_id: &record.proof_binding_id,
                session_id: "session:a5-launch",
            };
            let agent_id = agents::create(
                &self.data_dir,
                &caller,
                &agents::CreateRequest {
                    display_name: name.to_string(),
                    agent_host: PROBE_HOST.to_string(),
                    request_id: format!("request-{name}"),
                },
                |host| {
                    Ok(
                        crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                            host,
                            PROBE_REGISTRY_CID,
                            host_cid,
                        ),
                    )
                },
                2,
            )
            .unwrap()
            .agent_id;
            agents::set_active(&self.data_dir, &caller, &agent_id, true, 2).unwrap();
            agent_id
        }

        /// Writes a signed copy of the probe whose guest spins in `run` and
        /// asks the bridge for nothing. The manifest keeps the stored host's
        /// name (the launch grant names it) and the agent kind; only the
        /// entrypoint and its bytes differ. Returns the folder and the CID the
        /// Runtime's walk gives it.
        #[cfg(unix)]
        fn spin_host(&self) -> (std::path::PathBuf, String) {
            self.host_of("a5-spin-host", SPIN_COMPONENT)
        }

        /// [`Self::spin_host`] for the guest `wat`, in the folder `name`.
        #[cfg(unix)]
        fn host_of(&self, name: &str, wat: &str) -> (std::path::PathBuf, String) {
            use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};

            let key = SigningKey::from_bytes(&[0x44; 32]);
            let dir = self.fixture_root.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/a5-launch-probe");
            std::fs::copy(fixture.join("capsule.json"), dir.join("capsule.json")).unwrap();
            let wasm = wat::parse_str(wat).expect("the spin component compiles");
            std::fs::write(dir.join("spin.component.wasm"), &wasm).unwrap();
            let mut manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap();
            manifest.entrypoint = "spin.component.wasm".into();
            sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let cid = crate::stage_cmd::bundle_cid(&dir).expect("the spin host is walkable");
            (dir, cid)
        }

        pub(crate) fn root(&self, agent_id: &str) -> String {
            crate::auth::principal_stored_localhost_root(Some(&self.data_dir), agent_id).unwrap()
        }

        pub(crate) fn launch<'a>(
            &'a self,
            agent_id: &'a str,
        ) -> impl Future<Output = Result<Json<LaunchResponse>, (StatusCode, String)>> + 'a {
            self.launch_from(&self.capsule_dir, agent_id)
        }

        /// One stored agent's launch, with the probe's capability requests
        /// granted as the shell would grant them, and the activation waited
        /// out: the route answers `starting`, and the end is the registry's.
        pub(crate) async fn launch_with_grants(
            &self,
            agent_id: &str,
        ) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
            let grants =
                grant_probe_requests(self.pending_store.clone(), self.capability_manager.clone());
            let launched = self.launch(agent_id).await;
            if let Ok(answer) = &launched {
                self.wait_ended(&answer.0.session_id).await;
            }
            grants.abort();
            launched
        }

        pub(crate) async fn launched_instance_id(&self, agent_id: &str) -> String {
            let launched = self.launch_with_grants(agent_id).await.unwrap().0;
            assert_eq!(launched.status, crate::runtime::CAPSULE_STARTING);
            let ended = self.wait_ended(&launched.id).await;
            assert_eq!(ended.cause.as_deref(), Some("completed"));
            launched.id
        }

        /// Waits until the registry records this activation's end, and returns
        /// the entry: its status and cause are where a launch's outcome is
        /// now observable (`runtime.rs:start_loaded`).
        pub(crate) async fn wait_ended(&self, id: &str) -> crate::runtime::RunningCapsuleInfo {
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if let Some(info) = self.runtime.get_capsule(id).await {
                        if info.ended_at.is_some() {
                            break info;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("the activation {id} does not end"))
        }

        /// Wait for the watcher's state change after the guest's first call.
        #[cfg(unix)]
        pub(crate) async fn wait_running(&self, id: &str) -> crate::runtime::RunningCapsuleInfo {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(info) = self.runtime.get_capsule(id).await {
                        if info.status == "running" {
                            break info;
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("the activation {id} does not become running"))
        }

        /// Waits until this activation's own capability request reaches the
        /// pending store, the observable edge of "its guest is in the bridge".
        pub(crate) async fn wait_pending(
            &self,
            session: &str,
        ) -> elastos_runtime::capability::pending::PendingCapabilityRequest {
            let wanted = session.to_string();
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(request) = self
                        .pending_store
                        .list_pending()
                        .await
                        .into_iter()
                        .find(|request| request.session_id.0 == wanted)
                    {
                        break request;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{session} asks the shell for its first call"))
        }

        /// The list route's own answer for this Home's Runtime.
        #[cfg(unix)]
        pub(crate) async fn listed(&self) -> Vec<serde_json::Value> {
            let Json(list) = list_capsules(Extension(self.runtime.clone())).await;
            serde_json::to_value(&list).unwrap()["capsules"]
                .as_array()
                .expect("the list is an array")
                .clone()
        }

        /// The shell's capability state over this Home's stores: the views
        /// below read the same store and manager the bridge does.
        #[cfg(unix)]
        fn capability_state(&self) -> crate::api::handlers::CapabilityState {
            use crate::api::handlers::CapabilityState;
            use elastos_runtime::capability::evaluator::ShellPassthroughVerifier;
            use elastos_runtime::capability::PolicyEvaluator;
            CapabilityState {
                pending_store: self.pending_store.clone(),
                capability_manager: self.capability_manager.clone(),
                capability_store: self.capability_store.clone(),
                policy_evaluator: Arc::new(PolicyEvaluator::new(
                    Box::new(ShellPassthroughVerifier),
                    self.audit_log.clone(),
                )),
            }
        }

        /// `GET /api/capability/list?scope=all_sessions_live` as the shell: the
        /// live grants of every session.
        #[cfg(unix)]
        pub(crate) async fn live_view(&self) -> Vec<serde_json::Value> {
            use crate::api::handlers::capability::list_capabilities;
            use axum::extract::{Query, State};
            use elastos_runtime::session::Session;
            let state = self.capability_state();
            let uri = "http://runtime/api/capability/list?scope=all_sessions_live";
            let query = Query::try_from_uri(&uri.parse().unwrap()).unwrap();
            let shell = Extension(Session::new_shell("shell-vm".to_string()));
            let body = list_capabilities(State(state), shell, query)
                .await
                .expect("the shell may list every session's live grants");
            serde_json::to_value(body.0).unwrap()["capabilities"]
                .as_array()
                .expect("the live view is an array")
                .clone()
        }

        /// `GET /api/capability/pending` as the shell: every request still
        /// waiting for an answer.
        #[cfg(unix)]
        pub(crate) async fn pending_view(&self) -> Vec<serde_json::Value> {
            use crate::api::handlers::capability::list_pending;
            use axum::extract::State;
            use elastos_runtime::session::Session;
            let state = self.capability_state();
            let shell = Extension(Session::new_shell("shell-vm".to_string()));
            let body = list_pending(State(state), shell).await;
            serde_json::to_value(body.0).unwrap()["requests"]
                .as_array()
                .expect("the pending view is an array")
                .clone()
        }

        /// `GET /api/capability/requests?session=` as the shell: every record
        /// the store still holds for one session, with its settler.
        #[cfg(unix)]
        pub(crate) async fn request_view(&self, session: &str) -> Vec<serde_json::Value> {
            use crate::api::handlers::capability::{session_requests, SessionRequestsQuery};
            use axum::extract::{Query, State};
            use elastos_runtime::session::Session;
            let state = self.capability_state();
            let shell = Extension(Session::new_shell("shell-vm".to_string()));
            let query = Query(SessionRequestsQuery {
                session: Some(session.to_string()),
            });
            let body = session_requests(State(state), shell, query)
                .await
                .expect("the shell may read a session's records");
            serde_json::to_value(body.0).unwrap()["requests"]
                .as_array()
                .expect("the request view is an array")
                .clone()
        }

        /// One granted and one pending request in this instance's session, as
        /// a bridge leaves them: the ask it already spent, and the one it is
        /// still waiting on. Both name [`SEEDED_REQUEST_RESOURCE`], which a
        /// grant loop holds so the pending one stays pending.
        #[cfg(unix)]
        async fn seed_session_requests(&self, session: &str) -> (String, String) {
            use elastos_runtime::capability::pending::GrantDuration;
            use elastos_runtime::capability::{Action, ResourceId, TokenConstraints};
            let store = &self.pending_store;
            let manager = &self.capability_manager;
            let id = elastos_runtime::session::SessionId::from_string(session.to_string());
            let resource = ResourceId::new(SEEDED_REQUEST_RESOURCE);
            let granted = store
                .create_request(id.clone(), resource.clone(), Action::Write)
                .await
                .id
                .to_string();
            let token = manager.grant(
                session,
                resource.clone(),
                Action::Write,
                TokenConstraints::default(),
                None,
            );
            store
                .grant_request(&granted, token, GrantDuration::Session)
                .await
                .unwrap();
            let pending = store
                .create_request(id, resource, Action::Read)
                .await
                .id
                .to_string();
            (granted, pending)
        }

        /// The same launch from `dir`, which must walk to the bytes the agent's
        /// stored Agent Host names.
        fn launch_from<'a>(
            &'a self,
            dir: &'a std::path::Path,
            agent_id: &'a str,
        ) -> impl Future<Output = Result<Json<LaunchResponse>, (StatusCode, String)>> + 'a {
            let grant = gateway::issue_home_agent_launch_token_with_context(
                &self.data_dir,
                agent_id,
                PROBE_HOST,
                &self.context,
            )
            .unwrap();
            let agent_id = agent_id.to_string();
            let data_dir = Some(self.data_dir.clone());
            let runtime = self.runtime.clone();
            let audit_log = self.audit_log.clone();
            let path = dir.to_string_lossy().into_owned();
            async move {
                launch_capsule(
                    Extension(runtime),
                    Extension(audit_log),
                    Extension(data_dir),
                    Json(LaunchRequest {
                        path,
                        principal_id: None,
                        launch_grant: Some(grant),
                        agent_id: Some(agent_id),
                    }),
                )
                .await
            }
        }

        /// Every bridge call the persisted audit holds under `agent_id`, in
        /// order: the session it ran in, its outcome, and what it asked for.
        #[cfg(unix)]
        fn invoked(&self, agent_id: &str) -> Vec<(Option<String>, String, String)> {
            crate::auth::load_auth_state(&self.data_dir)
                .unwrap()
                .audit
                .iter()
                .filter(|event| event.event_type == "component.invoke.completed")
                .filter(|event| event.principal_id.as_deref() == Some(agent_id))
                .map(|event| {
                    (
                        event.session_id.clone(),
                        event.result.clone(),
                        event.reason.clone(),
                    )
                })
                .collect()
        }

        /// Every raw request the bridge routed to the capturing localhost
        /// double, in order.
        #[cfg(unix)]
        pub(crate) fn requests(&self) -> Vec<serde_json::Value> {
            self.provider.requests()
        }

        /// Every `CapabilityRequested` event's resource, in order. A request
        /// the bridge refuses before creating a record never appears here, so
        /// a refused spelling's absence is evidence it reached no store.
        #[cfg(unix)]
        pub(crate) fn capability_requested(&self) -> Vec<String> {
            self.audit_log
                .recent_events(usize::MAX)
                .into_iter()
                .filter_map(|event| match event {
                    elastos_runtime::primitives::audit::AuditEvent::CapabilityRequested {
                        resource,
                        ..
                    } => Some(resource),
                    _ => None,
                })
                .collect()
        }

        /// Writes the plan the guest reads under its own root and issues.
        #[cfg(unix)]
        pub(crate) fn plan(&self, agent_id: &str, lines: &[String]) {
            let root = self.root(agent_id);
            let uri = format!("{root}/memory/plan");
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&self.data_dir, &uri).unwrap();
            crate::auth::write_principal_root_object(
                &self.data_dir,
                agent_id,
                &root,
                &uri,
                &path,
                lines.join("\n").as_bytes(),
            )
            .unwrap();
        }

        /// The result line the guest wrote for each plan entry, in order.
        #[cfg(unix)]
        pub(crate) fn results(&self, agent_id: &str) -> Vec<String> {
            let root = self.root(agent_id);
            let uri = format!("{root}/memory/results");
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&self.data_dir, &uri).unwrap();
            let bytes = crate::auth::read_principal_root_object(
                &self.data_dir,
                agent_id,
                &root,
                &uri,
                &path,
            )
            .unwrap();
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    /// Every file under `dir` as (relative path, SHA-256 of its bytes), sorted.
    /// Two calls that return the same vector mean the tree's names and bytes
    /// did not change. Any part of the tree the walk cannot read fails the
    /// caller by name: a census that skips a subtree cannot prove a claim
    /// about the whole tree. A root that does not exist yet is an empty tree
    /// (callers snapshot a root before anything is written there); every
    /// error inside an existing tree still fails.
    #[cfg(unix)]
    pub(crate) fn tree_hashes(dir: &std::path::Path) -> Vec<(String, String)> {
        use sha2::{Digest, Sha256};
        match std::fs::symlink_metadata(dir) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
            Err(err) => panic!("cannot stat {}: {err}", dir.display()),
            Ok(_) => {}
        }
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let entries = std::fs::read_dir(dir)
                .unwrap_or_else(|err| panic!("cannot list {}: {err}", dir.display()));
            for entry in entries {
                let entry = entry.unwrap_or_else(|err| {
                    panic!("cannot read an entry of {}: {err}", dir.display())
                });
                let path = entry.path();
                let is_dir = std::fs::metadata(&path)
                    .unwrap_or_else(|err| panic!("cannot stat {}: {err}", path.display()))
                    .is_dir();
                if is_dir {
                    walk(root, &path, out);
                } else {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or_else(|err| {
                            panic!("{} is outside {}: {err}", path.display(), root.display())
                        })
                        .to_string_lossy()
                        .into_owned();
                    let bytes = std::fs::read(&path)
                        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
                    let digest = format!("{:x}", Sha256::digest(&bytes));
                    out.push((relative, digest));
                }
            }
        }
        let mut found = Vec::new();
        walk(dir, dir, &mut found);
        found.sort();
        found
    }

    /// What the code at the base commit answers one planned bridge call.
    #[derive(Clone, Copy, PartialEq, Eq)]
    #[cfg(unix)]
    enum PlanExpect {
        /// `principal_context_required` with the UsersAI scope sentence.
        Scope,
        /// `manifest_capability_denied` with the ceiling sentence.
        Ceiling,
        /// `invalid_resource_invoke` with the UsersAI scope sentence.
        Invalid,
        /// The capability request is granted: the spelling stays inside the
        /// agent's own root.
        HeldRequest,
        /// No refusal and no Y data: the held spelling's operation answer.
        HeldOperation,
        /// The bare area, normalized to `localhost://UsersAI`, is refused at
        /// the manifest ceiling: no stored root is named, so the request is
        /// junk (definition:36) and carries none of Y's data.
        BareArea,
        /// The same bare spelling driven as the operation itself, with X's
        /// held grant: the answer names no part of Y and is refused at the
        /// manifest ceiling before any provider or stored root is reached.
        BareAreaOperation,
    }

    /// The outcome column of the guest's result line for plan entry `index`.
    #[cfg(unix)]
    fn plan_outcome(results: &[String], index: usize) -> String {
        results
            .get(index)
            .unwrap_or_else(|| panic!("no result for plan entry {index}: {results:?}"))
            .split_once('\t')
            .unwrap_or_else(|| panic!("malformed result line for entry {index}: {results:?}"))
            .1
            .to_string()
    }

    /// Grants every pending capability request the probe makes, as the shell
    /// would, and keeps doing it until the test stops the task.
    pub(crate) fn grant_probe_requests(
        store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        manager: Arc<elastos_runtime::capability::CapabilityManager>,
    ) -> tokio::task::JoinHandle<()> {
        use elastos_runtime::capability::pending::GrantDuration;
        use elastos_runtime::capability::token::TokenConstraints;
        tokio::spawn(async move {
            loop {
                for pending in store.list_pending().await {
                    let token = manager.grant(
                        &pending.session_id.0,
                        pending.resource.clone(),
                        pending.action,
                        TokenConstraints::default(),
                        None,
                    );
                    let _ = store
                        .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                        .await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
    }

    /// Grants every pending request the named sessions make, as the shell
    /// would, and keeps doing it until the test stops the task. A request for
    /// a resource in `held` is left pending. Every grant the store accepts is
    /// pushed to `made`, so a row can check a token it made afterwards.
    #[cfg(unix)]
    pub(crate) fn grant_requests_of(
        store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        manager: Arc<elastos_runtime::capability::CapabilityManager>,
        sessions: Vec<String>,
        held: Vec<String>,
        made: Arc<std::sync::Mutex<Vec<elastos_runtime::capability::CapabilityToken>>>,
    ) -> tokio::task::JoinHandle<()> {
        use elastos_runtime::capability::pending::GrantDuration;
        use elastos_runtime::capability::token::TokenConstraints;
        tokio::spawn(async move {
            loop {
                for pending in store.list_pending().await {
                    if !sessions
                        .iter()
                        .any(|session| session == &pending.session_id.0)
                    {
                        continue;
                    }
                    if held
                        .iter()
                        .any(|held| held == &pending.resource.to_string())
                    {
                        continue;
                    }
                    let token = manager.grant(
                        &pending.session_id.0,
                        pending.resource.clone(),
                        pending.action,
                        TokenConstraints::default(),
                        None,
                    );
                    let granted = store
                        .grant_request(pending.id.as_str(), token.clone(), GrantDuration::Session)
                        .await;
                    if granted.is_ok() {
                        made.lock().unwrap().push(token);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
    }

    /// A5 admission row 1, at the launch entry with the feature on: two stored
    /// agents of one owner launch through `launch_capsule` with dev mode off.
    /// Each agent's own guest writes a format-2 journal entry and
    /// `memory/notes.md` through the bridge, reads both back, and its
    /// activation ends only when the bytes return: the route answers
    /// `starting`, and the registry entry records `stopped` with cause
    /// `completed` at the end. Each bridge call is audited under that agent's
    /// own id and root, and the same holds after a stop and relaunch. Row 6b
    /// rides here too: the manifest declares the agent kind and names no id,
    /// and the audited actor is still the id the request named.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agent_launch_binds_each_agents_own_principal_and_root() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());

        let first = home.launch(a).await.unwrap().0;
        let second = home.launch(b).await.unwrap().0;
        assert_eq!(first.status, "starting");
        assert_eq!(second.status, "starting");
        let first_end = home.wait_ended(&first.id).await;
        let second_end = home.wait_ended(&second.id).await;
        for end in [&first_end, &second_end] {
            assert_eq!(end.status, "stopped");
            assert_eq!(end.cause.as_deref(), Some("completed"));
        }

        // Each bridge call names that agent and its own capsule instance, and
        // carries the concrete URI the guest asked for through `UsersAI/self`.
        // Every completed bridge call also names the person the agent acts
        // for, in the existing `reason` field.
        let owner = home.owner.clone();
        let own_calls = |root: &str, session: &str| {
            let audit = |reason: String| format!("{reason} owner={owner}");
            vec![
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    audit(format!(
                        "write {root}/.AppData/Agents/agent-host/tasks/t1/journal"
                    )),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    audit(format!("write {root}/memory/notes.md")),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    audit(format!(
                        "read {root}/.AppData/Agents/agent-host/tasks/t1/journal"
                    )),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    audit(format!("read {root}/memory/notes.md")),
                ),
            ]
        };
        let peer_miss = |root: &str, session: &str| {
            (
                Some(session.to_string()),
                "error".to_string(),
                format!("read {root}/memory/peer owner={owner}"),
            )
        };
        // The fixture reads a plan under the agent's own root on every launch;
        // a launch without a plan records the miss and issues no entry.
        let plan_miss = |root: &str, session: &str| {
            (
                Some(session.to_string()),
                "error".to_string(),
                format!("read {root}/memory/plan owner={owner}"),
            )
        };
        let (root_a, root_b) = (home.root(a), home.root(b));
        assert_ne!(root_a, root_b);
        assert!(root_a.starts_with("localhost://UsersAI/"), "{root_a}");
        assert!(root_b.starts_with("localhost://UsersAI/"), "{root_b}");

        let mut expected_a = own_calls(&root_a, &first.id);
        expected_a.push(peer_miss(&root_a, &first.id));
        expected_a.push(plan_miss(&root_a, &first.id));
        let mut expected_b = own_calls(&root_b, &second.id);
        expected_b.push(peer_miss(&root_b, &second.id));
        expected_b.push(plan_miss(&root_b, &second.id));
        assert_eq!(home.invoked(a), expected_a);
        assert_eq!(home.invoked(b), expected_b);

        // The activation has ended: its entry is kept for its session, status
        // and cause, and a stop finds nothing left to stop: it answers the
        // recorded end and changes nothing. A new launch takes the same
        // principal and root, and its guest reads back both files the earlier
        // launch wrote.
        let ended = home.runtime.get_capsule(&first.id).await.expect("kept");
        let answer = home.runtime.stop_capsule_by_id(&first.id).await.unwrap();
        let answer = answer.expect("the ended entry answers");
        assert_eq!(
            (answer.status, answer.cause, answer.ended_at),
            (ended.status, ended.cause, ended.ended_at)
        );
        let again = home.launch(a).await.unwrap().0;
        assert_ne!(again.id, first.id);
        assert_eq!(home.root(a), root_a);
        home.wait_ended(&again.id).await;
        let mut relaunched = own_calls(&root_a, &again.id);
        relaunched.push(peer_miss(&root_a, &again.id));
        relaunched.push(plan_miss(&root_a, &again.id));
        let mut all = expected_a;
        all.extend(relaunched);
        assert_eq!(home.invoked(a), all);
        assert_eq!(
            home.invoked(b).len(),
            6,
            "the other agent's calls are untouched"
        );
        grants.abort();
    }

    /// A5 row 2, on disk. The same launch as row 1, then the Home's whole
    /// `UsersAI` area is walked: each of two stored agents' format-2 journal
    /// entry and `memory/notes.md` sits under the writing agent's own root,
    /// and the area holds nothing else. No copy sits under the other agent's
    /// root, and no stray file sits at the area root. Each file is the sealed
    /// object its own agent wrote: its envelope names that agent, that root
    /// and that URI, so the bytes under one root cannot be the other agent's
    /// object.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_journal_and_memory_sit_only_under_its_own_root_on_disk() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let agents = home.agents.clone();
        assert_eq!(agents.len(), 2, "two agents");
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        for agent in &agents {
            let launched = home.launch(agent).await.unwrap().0;
            assert_eq!(launched.status, "starting");
            let end = home.wait_ended(&launched.id).await;
            assert_eq!(
                (end.status.as_str(), end.cause.as_deref()),
                ("stopped", Some("completed"))
            );
        }
        grants.abort();

        // What the guest wrote through the bridge, as the row above reads it.
        let suffixes = [
            "/.AppData/Agents/agent-host/tasks/t1/journal",
            "/memory/notes.md",
        ];
        let mut expected: Vec<(String, String, String, String)> = Vec::new();
        for agent in &agents {
            let root = home.root(agent);
            for suffix in suffixes {
                let uri = format!("{root}{suffix}");
                let path =
                    elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &uri)
                        .expect("the guest's URI maps to a file path");
                let name = path
                    .strip_prefix(&home.data_dir)
                    .expect("the object is inside the data directory")
                    .to_string_lossy()
                    .into_owned();
                expected.push((name, agent.to_string(), root.clone(), uri));
            }
        }

        // Every object is the sealed envelope of the agent that wrote it, and
        // every name in the area is one of those objects.
        let area = home.data_dir.join("UsersAI");
        for (name, agent, root, uri) in &expected {
            let path = home.data_dir.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|err| panic!("{name} is not on disk under its own root: {err}"));
            let envelope: serde_json::Value = serde_json::from_slice(&bytes)
                .unwrap_or_else(|err| panic!("{name} is not a sealed object: {err}"));
            for (field, want) in [
                ("principal_id", agent.as_str()),
                ("localhost_root", root.as_str()),
                ("object_uri", uri.as_str()),
            ] {
                assert_eq!(
                    envelope.get(field).and_then(serde_json::Value::as_str),
                    Some(want),
                    "{name} is the object of another agent or another path"
                );
            }
        }
        let mut names: Vec<String> = tree_hashes(&area)
            .into_iter()
            .map(|(name, _)| format!("UsersAI/{name}"))
            .collect();
        let mut wanted: Vec<String> = expected.into_iter().map(|row| row.0).collect();
        names.sort();
        wanted.sort();
        assert_eq!(
            names, wanted,
            "the UsersAI area holds each agent's own journal and notes, and nothing else"
        );
    }

    /// A3-R proof row. Two agents of one Home are resident at once through the
    /// production launch route. A's launch returns while its guest runs, held
    /// in its own first bridge call; B's launch returns while A is still
    /// running. Two registry entries are `running` with distinct id, session
    /// and principal, and both end `stopped` with cause `completed` after
    /// their calls are granted.
    #[cfg(unix)]
    #[tokio::test]
    async fn two_agents_resident_at_once() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&["a", "b"]).await);
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };

        // Start A's real route request and wait for its first bridge call.
        // Keeping that request in a task makes the F-sync plant fail at B's
        // return edge, even when the planted route blocks A's own response.
        let a_home = home.clone();
        let a_name = a.clone();
        let a_task = tokio::spawn(async move { a_home.launch(&a_name).await });
        let a_pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(request) = home.pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("A is held in its own first bridge call");
        let a_id = a_pending.session_id.0.clone();

        // B's launch returns while A's guest is still inside that call.
        let b_home = home.clone();
        let b_name = b.clone();
        let b_task = tokio::spawn(async move { b_home.launch(&b_name).await });
        let b_launch = tokio::time::timeout(std::time::Duration::from_secs(5), b_task)
            .await
            .expect("the second launch returns while the first runs")
            .expect("B's route task stays alive")
            .unwrap()
            .0;
        let a_launch = tokio::time::timeout(std::time::Duration::from_secs(5), a_task)
            .await
            .expect("A's launch returns while its guest runs")
            .expect("A's route task stays alive")
            .unwrap()
            .0;
        assert_eq!(a_launch.status, "starting");
        assert_eq!(a_launch.session_id, a_launch.id);
        assert_eq!(a_launch.id, a_id);
        assert_eq!(b_launch.status, "starting");
        assert_eq!(b_launch.session_id, b_launch.id);
        assert_ne!(a_launch.id, b_launch.id, "two instances, two ids");
        home.wait_pending(&b_launch.id).await;
        // A pending call shows before the row's status moves from starting.
        home.wait_running(&b_launch.id).await;

        let a_now = home.wait_running(&a_launch.id).await;
        assert_eq!(a_now.status, "running", "A still runs after B's launch");
        assert_eq!(a_now.session_id, a_id);
        let held = home.pending_store.list_pending().await;
        assert!(
            held.iter()
                .any(|request| request.id.as_str() == a_pending.id.as_str()),
            "A is still held in its own first bridge call: {held:?}"
        );

        // `GET /api/capsules`: two running entries, sorted by id, each naming
        // its session.
        let listed = home.listed().await;
        assert_eq!(listed.len(), 2, "{listed:?}");
        assert!(
            listed[0]["id"].as_str() < listed[1]["id"].as_str(),
            "the list is sorted by id: {listed:?}"
        );
        for entry in &listed {
            assert_eq!(entry["status"], "running", "{entry}");
            assert_eq!(entry["session_id"], entry["id"], "{entry}");
            assert!(entry["cause"].is_null(), "{entry}");
        }
        // The list view deliberately names no principal; the registry's own
        // field is where admission's actor is asserted.
        let b_now = home.wait_running(&b_launch.id).await;
        assert_eq!(a_now.principal.as_deref(), Some(a.as_str()));
        assert_eq!(b_now.principal.as_deref(), Some(b.as_str()));
        assert_ne!(a_now.principal, b_now.principal, "two principals");

        // Release both guests: each is granted its own call, and both run to
        // an end with a cause.
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let a_end = home.wait_ended(&a_launch.id).await;
        let b_end = home.wait_ended(&b_launch.id).await;
        grants.abort();
        for end in [&a_end, &b_end] {
            assert_eq!(end.status, "stopped");
            assert_eq!(end.cause.as_deref(), Some("completed"));
        }

        // One launch per agent: every completed bridge call of each agent names
        // its one session, so neither was relaunched.
        for (agent, session) in [(a, &a_launch.id), (b, &b_launch.id)] {
            let sessions: std::collections::BTreeSet<String> = home
                .invoked(agent)
                .into_iter()
                .filter_map(|(session, _, _)| session)
                .collect();
            assert_eq!(sessions.len(), 1, "one launch for {agent}: {sessions:?}");
            assert!(sessions.contains(session), "the session is {session}");
        }
    }

    /// Installs the launch probe as this Home's signed Agent Host, under the
    /// publisher key the release fixture already uses. Create and launch both
    /// walk this one directory.
    #[cfg(unix)]
    fn install_probe_as_signed_agent_host() -> crate::installed_release::tests::Fixture {
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};

        let mut home = crate::installed_release::tests::Fixture::new();
        let probe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/a5-launch-probe");
        let wasm = std::fs::read(probe.join("a5-launch-probe.component.wasm")).unwrap();
        let mut manifest: elastos_common::CapsuleManifest =
            serde_json::from_slice(&std::fs::read(probe.join("capsule.json")).unwrap()).unwrap();
        manifest.name = "agent-host".to_string();
        manifest.signature = None;
        sign_capsule(
            &SigningKey::from_bytes(&[71; 32]),
            &mut manifest,
            &hash_content(&wasm),
        )
        .unwrap();
        let sha256 = "ab".repeat(32);
        let cid = "bafkreiagenthost";
        std::fs::write(
            home.data.join("components.json"),
            serde_json::to_vec(&serde_json::json!({
                "external": {"agent-host": {
                    "install_path": "capsules/agent-host",
                    "platforms": {(crate::setup::detect_platform()): {
                        "cid": cid,
                        "checksum": format!("sha256:{sha256}"),
                        "extract_path": "capsules/agent-host"
                    }}
                }},
                "capsules": {"agent-host": {"cid": cid, "sha256": sha256}},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
        home.bind_components();
        let dir = home.data.join("capsules").join("agent-host");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join(&manifest.entrypoint), &wasm).unwrap();
        std::fs::write(dir.join(".elastos-cid"), format!("{cid}\n")).unwrap();
        std::fs::write(dir.join(".elastos-artifact-sha256"), &sha256).unwrap();
        let admitted = crate::agent_admission::verify_agent_host(&home.data, "agent-host")
            .expect("the installed probe is an admitted Agent Host");
        assert_eq!(admitted.package().name, "agent-host");
        assert!(!admitted.package().bundle_cid.is_empty());
        home
    }

    /// An admin passkey owner on `data_dir`, with storage protection and a
    /// System launch token the create route accepts.
    #[cfg(unix)]
    fn route_owner(
        data_dir: &std::path::Path,
    ) -> (String, String, gateway::HomeLaunchTokenContext) {
        use elastos_runtime::auth::{AuthSessionGrantV1, PasskeyWebAuthnBinding, ProofBinding};

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let now = crate::auth::now_ts();
        let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
            credential_id: "u4-route-owner".to_string(),
            public_key: "gateway-test-public-key".to_string(),
            sign_count: 1,
            user_verified: true,
            origin: "https://elastos.elacitylabs.com".to_string(),
            rp_id: "elastos.elacitylabs.com".to_string(),
            created_at: now,
            last_used_at: now,
            revoked_at: None,
        });
        let principal_id = crate::auth::passkey_credential_principal_id(
            "elastos.elacitylabs.com",
            "u4-route-owner",
        )
        .unwrap();
        let principal = crate::auth::upsert_principal_for_binding_as_role_named(
            data_dir,
            binding,
            principal_id,
            crate::auth::RuntimePrincipalRole::Admin,
            Some("Route owner"),
            now,
        )
        .unwrap();
        crate::auth::store_test_principal_root_protection(data_dir, &principal.principal_id);
        let grant = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: format!("grant:{}", gateway::uuid_like_token()),
            session_id: format!("auth:{}", gateway::uuid_like_token()),
            principal_id: principal.principal_id.clone(),
            proof_binding_id: principal.proof_binding_id.clone(),
            issued_at: now,
            expires_at: now + 12 * 60 * 60,
            apps: vec![
                gateway::HOME_CAPSULE_ID.to_string(),
                gateway::SYSTEM_CAPSULE_ID.to_string(),
            ],
        };
        crate::auth::store_session_grant(data_dir, grant.clone()).unwrap();
        let token = gateway::issue_home_launch_token_for_auth_grant(
            data_dir,
            gateway::SYSTEM_CAPSULE_ID,
            &grant,
        )
        .unwrap();
        let context = gateway::HomeLaunchTokenContext::for_test(
            principal.principal_id.clone(),
            grant.session_id,
            Some(principal.proof_binding_id),
            grant.grant_id,
            crate::auth::PrincipalKind::Human,
        );
        (principal.principal_id, token, context)
    }

    #[cfg(unix)]
    async fn post_system(
        app: &axum::Router,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, String) {
        use axum::body::Body;
        use tower::ServiceExt;
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "localhost")
            .header("origin", "null")
            .header("x-elastos-home-token", token)
            .header("content-type", "application/json")
            .body(match body {
                Some(body) => Body::from(body.to_string()),
                None => Body::empty(),
            })
            .unwrap();
        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[cfg(unix)]
    async fn launch_installed(
        home: Arc<ProbeLaunch>,
        dir: std::path::PathBuf,
        grant: String,
        agent_id: String,
    ) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
        launch_capsule(
            Extension(home.runtime.clone()),
            Extension(home.audit_log.clone()),
            Extension(Some(home.data_dir.clone())),
            Json(LaunchRequest {
                path: dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: Some(grant),
                agent_id: Some(agent_id),
            }),
        )
        .await
    }

    /// U4 row. Two agents are created by `POST /api/apps/system/agents/create`,
    /// then each is launched by that stored id through `launch_capsule`. Each
    /// running instance is bound to its own stored id and record, neither
    /// instance is the other agent's id, and both run the one installed host.
    /// A created agent starts off, so the owner turns each one on through
    /// `POST /api/apps/system/agents/activate` before it launches.
    #[cfg(unix)]
    #[tokio::test]
    async fn two_route_created_ids_one_host() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home_files = install_probe_as_signed_agent_host();
        let data_dir = home_files.data.clone();
        let capsule_dir = data_dir.join("capsules").join("agent-host");
        let (owner, token, context) = route_owner(&data_dir);
        let app = crate::api::gateway::gateway_router(crate::api::gateway::GatewayState {
            provider_registry: None,
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            identity_manager: Arc::new(std::sync::OnceLock::new()),
            cache_dir: data_dir.clone(),
            data_dir: data_dir.clone(),
        });
        let enabled = post_system(&app, "/api/apps/system/agents/enable", &token, None).await;
        assert_eq!(enabled.0, StatusCode::OK, "{}", enabled.1);

        let mut created = Vec::new();
        for (name, request_id) in [
            ("Route One", "request-route-1"),
            ("Route Two", "request-route-2"),
        ] {
            let (status, body) = post_system(
                &app,
                "/api/apps/system/agents/create",
                &token,
                Some(serde_json::json!({
                    "display_name": name,
                    "agent_host": "agent-host",
                    "request_id": request_id
                })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            created.push(serde_json::from_str::<serde_json::Value>(&body).unwrap());
        }
        let a_id = created[0]["agent_id"].as_str().unwrap().to_string();
        let b_id = created[1]["agent_id"].as_str().unwrap().to_string();
        assert_ne!(a_id, b_id, "the route minted two ids");
        assert_eq!(created[0]["agent_host"], created[1]["agent_host"]);
        assert_eq!(created[0]["agent_host"]["name"], "agent-host");
        let host_cid = created[0]["agent_host"]["bundle_cid"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            !host_cid.is_empty(),
            "create stored the host's walked bytes"
        );

        let file = crate::agents::agent_file_path(&data_dir).unwrap();
        let stored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        let rows = stored["agents"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "the route wrote two records");
        for (id, view) in [(&a_id, &created[0]), (&b_id, &created[1])] {
            let row = rows
                .iter()
                .find(|row| row["record"]["principal_id"] == *id)
                .unwrap_or_else(|| panic!("no stored record for {id}"));
            let record = &row["record"];
            assert_eq!(record["principal_id"], *id);
            assert_eq!(record["owner"], owner);
            assert_eq!(
                record["localhost_root"],
                crate::auth::principal_kind_localhost_root(id, crate::auth::PrincipalKind::Agent)
            );
            assert_eq!(record["agent_host_package"], view["agent_host"]);
            assert!(record["retired_at"].is_null());
        }
        assert_ne!(
            rows[0]["record"]["localhost_root"], rows[1]["record"]["localhost_root"],
            "each stored record owns its own root"
        );
        for id in [&a_id, &b_id] {
            let (status, body) = post_system(
                &app,
                "/api/apps/system/agents/activate",
                &token,
                Some(serde_json::json!({ "agent_id": id, "active": true })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
        }

        let home = Arc::new(
            ProbeLaunch::over_home(
                data_dir.clone(),
                &owner,
                context.proof_binding_id().unwrap(),
                context.session_id(),
                &context,
                &[],
            )
            .await,
        );
        assert!(
            home.agents.is_empty(),
            "the launch fixture created no agent of its own"
        );

        let a_home = home.clone();
        let a_dir = capsule_dir.clone();
        let a_grant = gateway::issue_home_agent_launch_token_with_context(
            &data_dir,
            &a_id,
            "agent-host",
            &context,
        )
        .unwrap();
        let a_name = a_id.clone();
        let a_task =
            tokio::spawn(async move { launch_installed(a_home, a_dir, a_grant, a_name).await });
        let a_pending = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(request) = home.pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first route-created agent reaches its own bridge call");

        let b_home = home.clone();
        let b_dir = capsule_dir.clone();
        let b_grant = gateway::issue_home_agent_launch_token_with_context(
            &data_dir,
            &b_id,
            "agent-host",
            &context,
        )
        .unwrap();
        let b_name = b_id.clone();
        let b_task =
            tokio::spawn(async move { launch_installed(b_home, b_dir, b_grant, b_name).await });
        let b_launch = tokio::time::timeout(std::time::Duration::from_secs(10), b_task)
            .await
            .expect("the second launch returns while the first runs")
            .expect("the second launch task stays alive");
        let a_launch = tokio::time::timeout(std::time::Duration::from_secs(10), a_task)
            .await
            .expect("the first launch returns")
            .expect("the first launch task stays alive");
        assert_eq!(
            a_launch.as_ref().map(|answer| answer.0.status.as_str()),
            Ok("starting"),
            "first route-created launch is bound to its own stored id"
        );
        assert_eq!(
            b_launch.as_ref().map(|answer| answer.0.status.as_str()),
            Ok("starting"),
            "second route-created launch is bound to its own stored id"
        );
        let a_launch = a_launch.unwrap().0;
        let b_launch = b_launch.unwrap().0;
        assert_eq!(a_launch.id, a_pending.session_id.0);
        assert_ne!(a_launch.id, b_launch.id, "two instances");
        home.wait_pending(&b_launch.id).await;

        let a_now = home.wait_running(&a_launch.id).await;
        let b_now = home.wait_running(&b_launch.id).await;
        assert_eq!(a_now.name, "agent-host");
        assert_eq!(b_now.name, "agent-host", "both run on the same host");
        assert_eq!(
            a_now.principal.as_deref(),
            Some(a_id.as_str()),
            "first route-created launch is bound to its own stored id"
        );
        assert_eq!(
            b_now.principal.as_deref(),
            Some(b_id.as_str()),
            "second route-created launch is bound to its own stored id"
        );
        assert_ne!(
            a_now.principal.as_deref(),
            Some(b_id.as_str()),
            "the first agent does not launch as the second"
        );
        assert_ne!(
            b_now.principal.as_deref(),
            Some(a_id.as_str()),
            "the second agent does not launch as the first"
        );

        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let a_end = home.wait_ended(&a_launch.id).await;
        let b_end = home.wait_ended(&b_launch.id).await;
        grants.abort();
        for end in [&a_end, &b_end] {
            assert_eq!(end.status, "stopped");
            assert_eq!(end.cause.as_deref(), Some("completed"));
            assert_eq!(end.name, "agent-host");
        }
        for (agent, session) in [(&a_id, &a_launch.id), (&b_id, &b_launch.id)] {
            let sessions: std::collections::BTreeSet<String> = home
                .invoked(agent)
                .into_iter()
                .filter_map(|(session, _, _)| session)
                .collect();
            assert_eq!(
                sessions.iter().cloned().collect::<Vec<_>>(),
                vec![session.clone()],
                "{agent} ran only its own launch"
            );
        }
        let other = home.invoked(&a_id);
        assert!(
            other
                .iter()
                .all(|(session, _, _)| session.as_deref() != Some(b_launch.id.as_str())),
            "the first agent's calls are not the second launch"
        );
    }

    /// The launch answers `starting` with its session while its guest runs; the
    /// entry is `running` from the moment the worker reports `started` until the
    /// guest ends.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn the_launch_answers_starting_and_the_entry_runs_from_the_workers_started() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();

        // Keep this task on the current thread through the route return and
        // registry read. The watcher is spawned at the end of admission, so
        // it cannot observe the worker's `started` until this task yields.
        let answer = tokio::task::unconstrained(home.launch(&agent))
            .await
            .unwrap()
            .0;
        assert_eq!(answer.status, "starting");
        assert_eq!(answer.session_id, answer.id);
        let starting = tokio::task::unconstrained(home.runtime.get_capsule(&answer.id))
            .await
            .expect("admission registered the entry");
        assert_eq!(
            starting.status, "starting",
            "the registry starts at admission"
        );
        assert_eq!(starting.session_id, answer.id);
        assert_eq!(starting.principal.as_deref(), Some(agent.as_str()));
        assert_eq!(starting.cause, None);
        assert_eq!(starting.ended_at, None);
        home.wait_pending(&answer.id).await;
        let entry = home.wait_running(&answer.id).await;
        assert_eq!(entry.status, "running");
        assert_eq!(entry.session_id, answer.id);
        assert_eq!(entry.cause, None);
        assert_eq!(entry.ended_at, None);
        assert_eq!(entry.principal.as_deref(), Some(agent.as_str()));

        // End it so the Home is quiet.
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        home.wait_ended(&answer.id).await;
        grants.abort();
    }

    /// A worker that cannot enter the guest leaves the admitted entry failed
    /// with the start error; it never reports running.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_pre_guest_start_failure_ends_failed_with_its_cause() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let answer = tokio::task::unconstrained(home.launch(&agent))
            .await
            .unwrap()
            .0;
        assert_eq!(answer.status, "starting");
        let starting = tokio::task::unconstrained(home.runtime.get_capsule(&answer.id))
            .await
            .expect("admission registered the entry");
        assert_eq!(starting.status, "starting");
        tokio::task::unconstrained(home.runtime.remove_loaded_component_for_test(&answer.id)).await;
        let ended = home.wait_ended(&answer.id).await;
        assert_eq!(ended.status, "failed");
        let cause = ended.cause.expect("a start error has a cause");
        assert!(
            cause.contains("Capsule not found") || cause.contains("not found"),
            "{cause}"
        );
        assert!(ended.ended_at.is_some());
        assert_eq!(home.runtime.ceiling_of(&answer.id), None);
    }

    /// Dropping the route while registration waits releases the admission
    /// context and the loaded component through the launch guard.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_a_launch_before_registration_releases_its_context() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&["a"]).await);
        let agent = home.agents.first().expect("one agent").clone();
        let registry = home.runtime.hold_capsule_registry_for_test().await;
        let route_home = home.clone();
        let route = tokio::spawn(async move { route_home.launch(&agent).await });
        let held_id = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some((id, _)) = home.runtime.model_token_ceilings_held().first() {
                    break id.clone();
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the route holds its admitted model ceiling");
        route.abort();
        let _ = route.await;
        drop(registry);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if home.runtime.ceiling_of(&held_id).is_none()
                    && home
                        .runtime
                        .model_token_ceilings_held()
                        .iter()
                        .all(|(id, _)| id != &held_id)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a cancelled route releases its bridge context");
        assert!(home.runtime.get_capsule(&held_id).await.is_none());
    }

    /// A natural return ends the entry `stopped` with cause `completed`, and
    /// the list route carries the session and the cause.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_natural_return_ends_the_entry_stopped_with_cause_completed() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let answer = home.launch_with_grants(&agent).await.unwrap().0;
        assert_eq!(answer.status, "starting");

        let entry = home.wait_ended(&answer.id).await;
        assert_eq!(entry.status, "stopped");
        assert_eq!(entry.cause.as_deref(), Some("completed"));
        assert_eq!(entry.session_id, answer.id);
        assert!(entry.ended_at.is_some());

        let listed = home.listed().await;
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["id"], answer.id);
        assert_eq!(listed[0]["session_id"], answer.id);
        assert_eq!(listed[0]["status"], "stopped");
        assert_eq!(listed[0]["cause"], "completed");
        // Nothing of the activation is left behind: the ending watcher took
        // the ceiling and the principal with it.
        assert_eq!(home.runtime.ceiling_of(&answer.id), None);
        assert!(home
            .runtime
            .model_token_ceilings_held()
            .iter()
            .all(|(id, _)| id != &answer.id));
    }

    /// A guest that traps ends the entry `failed` with the trap's cause.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_trap_ends_the_entry_failed_with_its_cause() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_x, root_y) = (home.root(x), home.root(y));
        let peer = format!("{root_y}/memory/notes.md");
        // The guest reads this pointer under its own root, then asks for the
        // peer it names. The bridge refuses that ask at the principal scope,
        // and the guest returns the refusal as its run's error.
        let pointer_uri = format!("{root_x}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            x,
            &root_x,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();

        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let answer = home.launch(x).await.unwrap().0;
        assert_eq!(answer.status, "starting");
        let entry = home.wait_ended(&answer.id).await;
        grants.abort();
        assert_eq!(entry.status, "failed");
        let cause = entry.cause.expect("a failed entry records its cause");
        assert!(
            cause.contains(
                "localhost://UsersAI roots must use UsersAI/self or the active principal root"
            ),
            "{cause}"
        );
        assert!(cause.contains(&peer), "{cause}");

        let listed = home.listed().await;
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["status"], "failed");
        assert_eq!(listed[0]["cause"], cause);
    }

    /// A11-R's proof row. A's guest traps after a granted invoke (the pointer
    /// under its own root names B's file, and the bridge refuses the ask at
    /// the principal scope). A ends `failed` with that refusal as its cause:
    /// exactly one `capsule_stop` error audit names it, its grants are
    /// revoked, its guest ran once (five calls in one session), and it is
    /// never launched again. B, held in its own first call the whole time, is
    /// untouched and then completes.
    #[cfg(unix)]
    #[tokio::test]
    async fn trap_recorded_once() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_a, root_b) = (home.root(a), home.root(b));
        let peer = format!("{root_b}/memory/notes.md");
        let pointer_uri = format!("{root_a}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            a,
            &root_a,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();

        // Both agents launch. B is held in its own first call from here to the
        // end of the row: only A's session is granted.
        let run_a = home.launch(a).await.unwrap().0;
        assert_eq!(run_a.status, "starting");
        let run_b = home.launch(b).await.unwrap().0;
        assert_eq!(run_b.status, "starting");
        home.wait_pending(&run_a.id).await;
        home.wait_pending(&run_b.id).await;
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run_a.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let end = home.wait_ended(&run_a.id).await;
        grants.abort();

        assert_eq!(end.status, "failed");
        assert_eq!(end.session_id, run_a.id);
        let cause = end.cause.clone().expect("a trap records its cause");
        assert!(
            cause.contains(
                "localhost://UsersAI roots must use UsersAI/self or the active principal root"
            ),
            "{cause}"
        );
        assert!(cause.contains(&peer), "{cause}");

        // A ran once. Its one session holds its five calls: four under its own
        // root and the read of the pointer. A relaunch would add a second
        // session and five more calls.
        let invoked_a = home.invoked(a);
        let sessions: std::collections::BTreeSet<Option<String>> = invoked_a
            .iter()
            .map(|(session, _, _)| session.clone())
            .collect();
        assert_eq!(
            sessions,
            std::collections::BTreeSet::from([Some(run_a.id.clone())]),
            "one launch for A: {sessions:?}"
        );
        assert_eq!(invoked_a.len(), 5, "{invoked_a:?}");

        // Its grants are revoked: every request of its session is denied by
        // the Runtime, with a reason that names the cause.
        let settled = format!("instance ended: {cause}");
        let a_requests: Vec<_> = home
            .pending_store
            .list_requests()
            .await
            .into_iter()
            .filter(|request| request.session_id.0 == run_a.id)
            .collect();
        assert!(!a_requests.is_empty(), "A asked for its own root");
        for request in &a_requests {
            let elastos_runtime::capability::RequestStatus::Denied { reason, settled_by } =
                &request.status
            else {
                panic!(
                    "a request of A's session is not denied: {:?}",
                    request.status
                );
            };
            assert_eq!(reason, &settled);
            assert_eq!(*settled_by, elastos_runtime::capability::Settler::Runtime);
        }

        // Exactly one `capsule_stop`, and it carries the error.
        let stops: Vec<_> = home
            .audit_log
            .recent_events(usize::MAX)
            .into_iter()
            .filter_map(|event| match event {
                elastos_runtime::primitives::audit::AuditEvent::CapsuleStop {
                    capsule_id,
                    reason,
                    ..
                } if capsule_id == run_a.id => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(stops.len(), 1, "exactly one stop audit: {stops:?}");
        assert!(
            matches!(
                &stops[0],
                elastos_runtime::primitives::audit::StopReason::Error(detail) if detail == &cause
            ),
            "{stops:?}"
        );

        // B is unaffected: its first call is still pending, its entry still
        // running.
        assert!(
            home.pending_store
                .list_pending()
                .await
                .iter()
                .any(|request| request.session_id.0 == run_b.id),
            "A's end settled no request of B's session"
        );
        assert_eq!(
            home.runtime
                .get_capsule(&run_b.id)
                .await
                .expect("B is still registered")
                .status,
            "running"
        );

        // A is not launched again. For two seconds after its end the registry
        // holds exactly A's one end and B's one run: a relaunch of the failed
        // activation would register a third instance (F-relaunch).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let listed = home.listed().await;
            assert_eq!(listed.len(), 2, "A was launched again: {listed:?}");
            if std::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // B completes when its own calls are granted.
        let b_grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run_b.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let b_end = home.wait_ended(&run_b.id).await;
        b_grants.abort();
        assert_eq!(b_end.status, "stopped");
        assert_eq!(b_end.cause.as_deref(), Some("completed"));
        assert_eq!(home.invoked(b).len(), 6, "{:?}", home.invoked(b));
    }

    /// A failed activation's end settles its session: a request still pending
    /// when the guest traps is denied by the Runtime with a reason that names
    /// the cause, and the grant it made before the trap no longer validates.
    /// A pending request of another session is left pending.
    #[cfg(unix)]
    #[tokio::test]
    async fn failure_settles_and_revokes() {
        use elastos_runtime::capability::manager::ValidationError;
        use elastos_runtime::capability::{Action, ResourceId};
        use elastos_runtime::session::SessionId;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_a, root_b) = (home.root(a), home.root(b));
        let peer = format!("{root_b}/memory/notes.md");
        let pointer_uri = format!("{root_a}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            a,
            &root_a,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();

        // A launches and stays held in its first call, so its session exists
        // and this row can put a request of that session in the store with the
        // call the bridge itself makes when a guest asks.
        let run = home.launch(a).await.unwrap().0;
        assert_eq!(run.status, "starting");
        home.wait_pending(&run.id).await;
        let reserved = ResourceId::new("elastos://content/publish");
        let reserved_id = home
            .pending_store
            .create_request(
                SessionId::from_string(run.id.clone()),
                reserved.clone(),
                Action::Read,
            )
            .await
            .id
            .to_string();

        // B's own request is pending too, and stays so across A's end.
        let run_b = home.launch(b).await.unwrap().0;
        let b_pending = home.wait_pending(&run_b.id).await;

        // A's calls are granted, except the reserved request, which A never
        // asked for and which stays pending until A ends.
        let made = Arc::new(std::sync::Mutex::new(Vec::new()));
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run.id.clone()],
            vec![reserved.to_string()],
            made.clone(),
        );
        let end = home.wait_ended(&run.id).await;
        grants.abort();
        assert_eq!(end.status, "failed");
        let cause = end.cause.clone().expect("a trap records its cause");

        // The request pending at the end is denied by the Runtime, and its
        // reason names the cause.
        let settled = format!("instance ended: {cause}");
        let after = home
            .pending_store
            .get_request(&reserved_id)
            .await
            .expect("the reserved request is still held");
        let elastos_runtime::capability::RequestStatus::Denied { reason, settled_by } =
            &after.status
        else {
            panic!("the pending request is not settled: {:?}", after.status);
        };
        assert_eq!(reason, &settled);
        assert_eq!(*settled_by, elastos_runtime::capability::Settler::Runtime);

        // B's request was not settled by A's end.
        assert!(
            home.pending_store
                .list_pending()
                .await
                .iter()
                .any(|request| request.id.as_str() == b_pending.id.as_str()),
            "A's end left B's request pending"
        );

        // Every grant A held before the trap is revoked in the token store.
        let made = made.lock().unwrap().clone();
        assert!(!made.is_empty(), "A's own-root calls were granted");
        for token in &made {
            assert_eq!(
                home.capability_manager
                    .validate(token, &run.id, token.action(), token.resource(), None)
                    .await,
                Err(ValidationError::TokenRevoked),
                "a grant of A's session survives its end"
            );
        }

        // B finishes on its own calls, so the Home is quiet.
        let b_grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run_b.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let b_end = home.wait_ended(&run_b.id).await;
        b_grants.abort();
        assert_eq!(b_end.status, "stopped");
        assert_eq!(b_end.cause.as_deref(), Some("completed"));
    }

    /// Writes the pointer `agent`'s guest reads under its own root: it names
    /// `peer`'s notes, which the bridge refuses at the principal scope, so
    /// the guest traps with that refusal. Returns the peer's file.
    #[cfg(unix)]
    fn point_at_peer(home: &ProbeLaunch, agent: &str, peer: &str) -> String {
        let (root, peer_root) = (home.root(agent), home.root(peer));
        let peer_file = format!("{peer_root}/memory/notes.md");
        let pointer_uri = format!("{root}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            agent,
            &root,
            &pointer_uri,
            &pointer_path,
            peer_file.as_bytes(),
        )
        .unwrap();
        peer_file
    }

    /// Every `capsule_stop` the Home audited for instance `id`, in order.
    #[cfg(unix)]
    fn stops_of(
        home: &ProbeLaunch,
        id: &str,
    ) -> Vec<elastos_runtime::primitives::audit::StopReason> {
        home.audit_log
            .recent_events(usize::MAX)
            .into_iter()
            .filter_map(|event| match event {
                elastos_runtime::primitives::audit::AuditEvent::CapsuleStop {
                    capsule_id,
                    reason,
                    ..
                } if capsule_id == id => Some(reason),
                _ => None,
            })
            .collect()
    }

    #[cfg(unix)]
    const SCOPE_REFUSAL: &str =
        "localhost://UsersAI roots must use UsersAI/self or the active principal root";

    /// A3-R S3 fix 1 row, and fix 2 row 1. The Home's saved revoke list
    /// cannot be replaced while two activations end: A traps and B returns.
    /// Each grant is refused in this process at once. The saved list lacks
    /// them, so each end is recorded `failed`, with a cause that names the
    /// revoke it could not save and the pending revocation list that kept it,
    /// and its one `capsule_stop` carries that cause. The Home restarted from
    /// its store and that list refuses every grant; the store alone would
    /// accept them.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unsaved_revoke_ends_the_activation_unsettled() {
        use elastos_runtime::capability::manager::ValidationError;
        use elastos_runtime::primitives::audit::StopReason;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::with_saved_revokes(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let peer = point_at_peer(&home, a, b);
        // The replacement of the saved list cannot be renamed over a folder.
        std::fs::create_dir(home.tokens_dir().join("revoked_tokens")).unwrap();

        let run_a = home.launch(a).await.unwrap().0;
        let run_b = home.launch(b).await.unwrap().0;
        let made = Arc::new(std::sync::Mutex::new(Vec::new()));
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run_a.id.clone(), run_b.id.clone()],
            Vec::new(),
            made.clone(),
        );
        let end_a = home.wait_ended(&run_a.id).await;
        let end_b = home.wait_ended(&run_b.id).await;
        grants.abort();

        for (end, outcome) in [(&end_a, peer.as_str()), (&end_b, "completed")] {
            assert_eq!(end.status, "failed", "{end:?}");
            let cause = end.cause.clone().expect("an end records its cause");
            assert!(cause.contains(outcome), "{cause}");
            assert!(
                cause.contains("; revocation not saved: "),
                "the end names the revoke it could not save: {cause}"
            );
            assert!(
                cause.ends_with("; kept in pending revocations"),
                "the end names the list that kept it: {cause}"
            );
            let stops = stops_of(&home, &end.id);
            assert!(
                matches!(stops.as_slice(), [StopReason::Error(detail)] if detail == &cause),
                "one stop audit with the recorded cause: {stops:?}"
            );
        }
        assert!(
            end_a.cause.as_deref().unwrap().contains(SCOPE_REFUSAL),
            "{end_a:?}"
        );

        let made = made.lock().unwrap().clone();
        assert!(!made.is_empty(), "both sessions were granted");
        let saved_alone = home.saved_store_tokens().await;
        let restarted = home.restarted_tokens().await;
        for token in &made {
            let session = token.capsule().to_string();
            let here = home
                .capability_manager
                .validate(token, &session, token.action(), token.resource(), None)
                .await;
            assert_eq!(here, Err(ValidationError::TokenRevoked), "in this process");
            let alone = saved_alone
                .validate(token, &session, token.action(), token.resource(), None)
                .await;
            assert_eq!(alone, Ok(()), "the saved store alone lacks the revoke");
            let after = restarted
                .validate(token, &session, token.action(), token.resource(), None)
                .await;
            assert_eq!(
                after,
                Err(ValidationError::TokenRevoked),
                "refused after a restart"
            );
        }
    }

    /// A3-R S3 fix 1 row: a stop and A's trap race, in both orders.
    /// First the stop reads A's entry while A's end waits to record the trap;
    /// the stop then answers the trap's end, and A's record is the trap's.
    /// Then a second run is stopped while its guest is held in its first
    /// call; the stop leaves the entry to the run's own end. Each run ends
    /// exactly once, with one cause and one `capsule_stop` that carries it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_racing_a_trap_ends_once() {
        use elastos_runtime::primitives::audit::StopReason;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let peer = point_at_peer(&home, a, b);

        let run = home.launch(a).await.unwrap().0;
        home.wait_pending(&run.id).await;
        home.wait_running(&run.id).await;
        // The registry is held: the stop's read of the entry waits first in
        // line, and A's end, which records last, waits behind it.
        let registry = home.runtime.hold_capsule_registry_for_test().await;
        let stopper = {
            let runtime = home.runtime.clone();
            let id = run.id.clone();
            tokio::spawn(async move { runtime.stop_capsule_by_id(&id).await.unwrap() })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while stops_of(&home, &run.id).is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("A traps and its end audits the stop");
        drop(registry);
        let stopped = stopper.await.unwrap();
        grants.abort();

        let end = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("the trap's record survives the racing stop");
        assert!(end.ended_at.is_some(), "{end:?}");
        assert_eq!(end.status, "failed", "{end:?}");
        let cause = end.cause.clone().expect("a trap records its cause");
        assert!(cause.contains(SCOPE_REFUSAL), "{cause}");
        assert!(cause.contains(&peer), "{cause}");
        let stopped = stopped.expect("the stop answers A's entry");
        assert_eq!(
            (stopped.status.as_str(), stopped.cause.as_deref()),
            ("failed", Some(cause.as_str())),
            "the stop answers the trap's end"
        );
        let stops = stops_of(&home, &run.id);
        assert!(
            matches!(stops.as_slice(), [StopReason::Error(detail)] if detail == &cause),
            "one stop audit, the trap's: {stops:?}"
        );

        let second = home.launch(a).await.unwrap().0;
        home.wait_pending(&second.id).await;
        home.wait_running(&second.id).await;
        assert!(
            home.runtime
                .stop_capsule_by_id(&second.id)
                .await
                .unwrap()
                .is_some(),
            "a live run is asked to stop"
        );
        assert!(
            home.runtime.get_capsule(&second.id).await.is_some(),
            "the stop leaves the entry to the run's own end"
        );
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![second.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let end = home.wait_ended(&second.id).await;
        grants.abort();
        let cause = end.cause.clone().expect("an end records its cause");
        let stops = stops_of(&home, &second.id);
        let agrees = match (end.status.as_str(), stops.as_slice()) {
            ("stopped", [StopReason::Requested]) => cause == "stopped: user",
            ("failed", [StopReason::Error(detail)]) => detail == &cause,
            _ => false,
        };
        assert!(
            agrees,
            "one end, one cause, one stop audit: {end:?} {stops:?}"
        );
        assert_eq!(home.listed().await.len(), 2, "two runs, each ended once");
    }

    /// The stop route as the API exposes it: `None` is the bodyless request.
    #[cfg(unix)]
    pub(crate) async fn stop_route(
        home: &ProbeLaunch,
        id: &str,
        reason: Option<&str>,
    ) -> (StatusCode, String) {
        let body = reason
            .map(|reason| serde_json::to_vec(&serde_json::json!({ "reason": reason })).unwrap())
            .unwrap_or_default();
        stop_route_with(home, id, body).await
    }

    /// The stop route with these exact body bytes.
    #[cfg(unix)]
    async fn stop_route_with(home: &ProbeLaunch, id: &str, body: Vec<u8>) -> (StatusCode, String) {
        let response = stop_capsule(
            Extension(home.runtime.clone()),
            Path(id.to_string()),
            body.into(),
        )
        .await;
        answer_of(response).await
    }

    /// A response's status and body text.
    #[cfg(unix)]
    async fn answer_of(response: axum::response::Response) -> (StatusCode, String) {
        use axum::body::to_bytes;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    /// The stop route's answer for an activation that has ended: its status
    /// and cause, as the list names them.
    #[cfg(unix)]
    fn stop_answer(body: &str) -> (String, Option<String>) {
        let answer: serde_json::Value = serde_json::from_str(body).expect("a JSON answer");
        (
            answer["status"].as_str().expect("a status").to_string(),
            answer["cause"].as_str().map(str::to_string),
        )
    }

    /// Launch, dispatch, and Stop go through the product path. This row does
    /// not bind an instance or mark one ending. The plan book is the one the
    /// hostcall closure receives. The guest stays inside its bridge call, so
    /// the run does not end on its own fuel. The second step is submitted
    /// while that call is still up. Its refusal is read after `end_instance`
    /// marks the instance and before `release` drops the admission: a dispatch
    /// after that drop is `admission_missing` and cannot see the mark.
    /// Deleting the hostcall's plan book, the bind in `start_loaded` (before
    /// `watch_activation`), or `mark_stopping` in `end_instance` fails this row.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_launched_run_stops_through_the_product_route() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = std::sync::Arc::new(ProbeLaunch::new(&["route"]).await);
        let agent = home.agents[0].clone();
        let launched = home.launch(&agent).await.expect("launch").0;
        assert_eq!(launched.status, crate::runtime::CAPSULE_STARTING);
        assert_eq!(launched.session_id, launched.id);
        let session = launched.id.clone();
        home.wait_pending(&session).await;

        let root = home.root(&agent);
        let target = format!("{root}/Documents/plan.md");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &target).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            &agent,
            &root,
            &target,
            &path,
            b"before",
        )
        .unwrap();
        let before = std::fs::read(&path).unwrap();
        let book = home.runtime.plan_book();

        assert!(
            crate::runtime::Runtime::plan_instance_is_open(&book, &session, &agent),
            "the launch did not bind {session} for {agent}"
        );
        let first = submit_launched_plan(&home, &session, &agent, &target, vec![1]).await;
        assert_eq!(
            crate::resource_bridge::retained_plan_instance_is_open(&first, &session, &agent, &book),
            "open",
            "the hostcall context does not see the launched instance"
        );
        let second = submit_launched_plan(&home, &session, &agent, &target, vec![2]).await;
        approve_launched_plan(&home.data_dir, &first);
        let pause = crate::resource_bridge::arm_plan_dispatch_hold(
            &first,
            crate::resource_bridge::PlanDispatchPoint::InEffect,
        );
        let state = launched_plan_state(&home);
        let owner = home.owner.clone();
        let request = first.clone();
        let task = tokio::spawn(async move {
            gateway::dispatch_approved_agent_plan(
                &state,
                &gateway::HomeLaunchTokenContext::for_test(
                    owner,
                    "session:owner",
                    None,
                    "grant:owner",
                    crate::auth::PrincipalKind::Human,
                ),
                &request,
            )
            .await
        });
        let reached =
            tokio::time::timeout(std::time::Duration::from_secs(20), pause.entered.notified())
                .await;
        if reached.is_err() {
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
            let stored = std::fs::read(
                home.data_dir
                    .join("inspect-actions")
                    .join(format!("{first}.json")),
            )
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default();
            panic!("the launched dispatch did not reach its effect: {outcome:?}\n{stored}");
        }

        let end_pause = crate::runtime::arm_after_plan_end_mark(&session);
        let _release_end = NotifyOnDrop(std::sync::Arc::clone(&end_pause.release));
        let stop_home = std::sync::Arc::clone(&home);
        let stop_agent = agent.clone();
        let stop_task =
            tokio::spawn(async move { stop_launched_agent(&stop_home, &stop_agent).await });
        let marked = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            end_pause.entered.notified(),
        )
        .await;
        if marked.is_err() {
            let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), stop_task).await;
            panic!("the stop did not mark the end: {outcome:?}");
        }

        approve_launched_plan(&home.data_dir, &second);
        let refused = gateway::dispatch_approved_agent_plan(
            &launched_plan_state(&home),
            &gateway::HomeLaunchTokenContext::for_test(
                home.owner.clone(),
                "session:owner",
                None,
                "grant:owner",
                crate::auth::PrincipalKind::Human,
            ),
            &second,
        )
        .await
        .expect("a refused step still settles");
        assert!(refused.contains("refused"), "{refused}");
        let record = std::fs::read(
            home.data_dir
                .join("inspect-actions")
                .join(format!("{second}.json")),
        )
        .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(record["status"], "refused", "{record}");
        assert_eq!(record["result"]["code"], "instance ended", "{record}");
        assert_eq!(std::fs::read(&path).unwrap(), before);

        end_pause.release.notify_one();
        let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(20), stop_task)
            .await
            .expect("the stop did not answer")
            .expect("stop task");
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let stopping = body["stopping"].as_array().expect("stopping");
        assert!(
            stopping
                .iter()
                .any(|row| row["session_id"] == session && row["status"] == "stopping"),
            "{body}"
        );

        pause.release.notify_one();
        let finished = tokio::time::timeout(std::time::Duration::from_secs(20), task)
            .await
            .expect("the launched effect did not settle");
        finished.expect("dispatch task").expect("dispatch");
    }

    /// An effect in flight keeps the live-run token after the end is decided.
    /// Start is refused until that effect is settled, and the same grant is
    /// then allowed. An unknown record releases the token on the same path.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_start_waits_until_an_inflight_effect_is_settled() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = std::sync::Arc::new(ProbeLaunch::new(&["token"]).await);
        let agent = home.agents[0].clone();
        let launched = home.launch(&agent).await.expect("launch").0;
        assert_eq!(launched.session_id, launched.id);
        let session = launched.id.clone();
        home.wait_pending(&session).await;

        let root = home.root(&agent);
        let target = format!("{root}/Documents/plan.md");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &target).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            &agent,
            &root,
            &target,
            &path,
            b"before",
        )
        .unwrap();

        let first = submit_launched_plan(&home, &session, &agent, &target, vec![1]).await;
        approve_launched_plan(&home.data_dir, &first);
        let pause = crate::resource_bridge::arm_plan_dispatch_hold(
            &first,
            crate::resource_bridge::PlanDispatchPoint::InEffect,
        );
        let state = launched_plan_state(&home);
        let owner = home.owner.clone();
        let request = first.clone();
        let task = tokio::spawn(async move {
            gateway::dispatch_approved_agent_plan(
                &state,
                &gateway::HomeLaunchTokenContext::for_test(
                    owner,
                    "session:owner",
                    None,
                    "grant:owner",
                    crate::auth::PrincipalKind::Human,
                ),
                &request,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(20), pause.entered.notified())
            .await
            .expect("the effect did not start");

        let (status, body) = stop_launched_agent(&home, &agent).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert!(
            home.runtime.agent_live_run_held(&agent),
            "the end released the token while an effect was in flight"
        );
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            &agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        assert_stopping(launch_grant(&home, &home.capsule_dir, &agent, &grant).await);
        assert!(
            home.runtime.stop_requested_for_test(&agent).await,
            "Start cleared the stop mark while an effect was in flight"
        );

        pause.release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(20), task)
            .await
            .expect("the effect did not settle")
            .expect("dispatch task")
            .expect("dispatch");
        assert!(
            !home.runtime.agent_live_run_held(&agent),
            "a settled effect left the live run held"
        );
        let again = launch_grant(&home, &home.capsule_dir, &agent, &grant)
            .await
            .expect("the settled effect allows Start");
        let _ = stop_launched_agent(&home, &agent).await;
        assert_ne!(again.0.id, session);
    }

    /// A timeout resolves the flight. Start is refused while it is landing
    /// and allowed once the record is unknown.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_start_is_allowed_after_the_effect_is_unknown() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = std::sync::Arc::new(ProbeLaunch::new(&["unknown-start"]).await);
        let agent = home.agents[0].clone();
        let launched = home.launch(&agent).await.expect("launch").0;
        let session = launched.id.clone();
        home.wait_pending(&session).await;
        let root = home.root(&agent);
        let target = format!("{root}/Documents/plan.md");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &target).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            &agent,
            &root,
            &target,
            &path,
            b"before",
        )
        .unwrap();
        let first = submit_launched_plan(&home, &session, &agent, &target, vec![1]).await;
        approve_launched_plan(&home.data_dir, &first);
        gateway::set_plan_dispatch_wait_for_test(&first, std::time::Duration::from_secs(2));
        let pause = crate::resource_bridge::arm_plan_dispatch_hold(
            &first,
            crate::resource_bridge::PlanDispatchPoint::InEffect,
        );
        let state = launched_plan_state(&home);
        let owner = home.owner.clone();
        let request = first.clone();
        let task = tokio::spawn(async move {
            gateway::dispatch_approved_agent_plan(
                &state,
                &gateway::HomeLaunchTokenContext::for_test(
                    owner,
                    "session:owner",
                    None,
                    "grant:owner",
                    crate::auth::PrincipalKind::Human,
                ),
                &request,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(20), pause.entered.notified())
            .await
            .expect("the effect did not start");
        let (status, body) = stop_launched_agent(&home, &agent).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            &agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        assert_stopping(launch_grant(&home, &home.capsule_dir, &agent, &grant).await);
        tokio::time::timeout(std::time::Duration::from_secs(20), task)
            .await
            .expect("the timeout did not settle")
            .expect("dispatch task")
            .expect("dispatch");
        gateway::clear_plan_dispatch_wait_for_test(&first);
        let stored = std::fs::read(
            home.data_dir
                .join("inspect-actions")
                .join(format!("{first}.json")),
        )
        .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(record["status"], "unknown", "{record}");
        let again = launch_grant(&home, &home.capsule_dir, &agent, &grant)
            .await
            .expect("an unknown record left Start refused");
        assert_ne!(again.0.id, session);
    }

    /// The plan instance is bound before the guest's first line.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_guest_that_dispatches_at_once_sees_the_instance() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = std::sync::Arc::new(ProbeLaunch::new(&["dispatch-at-once"]).await);
        let agent = home.agents[0].clone();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        crate::runtime::arm_guest_opening(&agent, crate::runtime::GuestOpening::Dispatch(sender));
        let launched = home.launch(&agent).await.expect("launch").0;
        let open = tokio::time::timeout(std::time::Duration::from_secs(10), receiver)
            .await
            .expect("the guest did not start")
            .expect("the guest dropped the answer");
        assert!(
            open,
            "the instance was not bound before the guest ran: {}",
            crate::runtime::Runtime::plan_book_view(&home.runtime.plan_book(), &launched.id)
        );
        let _ = stop_launched_agent(&home, &agent).await;
    }

    /// A guest that ends at once does not leave a plan instance behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_guest_that_exits_at_once_does_not_leave_an_instance() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = std::sync::Arc::new(ProbeLaunch::new(&["exit-at-once"]).await);
        let agent = home.agents[0].clone();
        crate::runtime::arm_guest_opening(&agent, crate::runtime::GuestOpening::Exit);
        let launched = home.launch(&agent).await.expect("launch").0;
        let session = launched.id.clone();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match home.runtime.get_capsule(&session).await {
                    Some(info) if info.ended_at.is_some() => break,
                    None => break,
                    Some(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        assert!(ended.is_ok(), "the guest did not end");
        assert!(
            !crate::runtime::Runtime::plan_instance_is_open(
                &home.runtime.plan_book(),
                &session,
                &agent
            ),
            "an instance remained: {}",
            crate::runtime::Runtime::plan_book_view(&home.runtime.plan_book(), &session)
        );
    }

    /// Releases a plan-end pause if the row fails before it does.
    #[cfg(unix)]
    struct NotifyOnDrop(std::sync::Arc<tokio::sync::Notify>);

    #[cfg(unix)]
    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    #[cfg(unix)]
    async fn submit_launched_plan(
        home: &ProbeLaunch,
        session: &str,
        agent: &str,
        target: &str,
        content: Vec<u8>,
    ) -> String {
        use elastos_runtime::capability::{Action, ResourceId, TokenConstraints};
        let token = home.capability_manager.grant(
            session,
            ResourceId::new("elastos://inspect/submit_agent_plan"),
            Action::Write,
            TokenConstraints::default(),
            None,
        );
        let token = token.to_base64().expect("token encodes");
        let plan = serde_json::json!({
            "steps": [{
                "scheme": "localhost",
                "operation": "write",
                "request": {"path": target, "content": content}
            }]
        });
        let line = serde_json::json!({
            "id": 1,
            "request": {
                "type": "resource_invoke",
                "uri": "elastos://inspect/submit_agent_plan",
                "operation": "submit_agent_plan",
                "body": plan,
                "token": token,
            }
        })
        .to_string();
        let runtime = home.runtime.clone();
        let session = session.to_string();
        let agent = agent.to_string();
        let raw = tokio::task::spawn_blocking(move || {
            runtime.call_component_hostcall_for_test(&line, &session, Some(&agent))
        })
        .await
        .expect("hostcall task")
        .expect("hostcall");
        let answer: serde_json::Value = serde_json::from_str(&raw).expect(&raw);
        answer["response"]["result"]["data"]["request_id"]
            .as_str()
            .unwrap_or_else(|| panic!("submit did not return a request: {answer}"))
            .to_string()
    }

    #[cfg(unix)]
    fn approve_launched_plan(data_dir: &std::path::Path, request_id: &str) {
        let path = data_dir
            .join("inspect-actions")
            .join(format!("{request_id}.json"));
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["status"] = serde_json::json!("approved");
        std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    }

    #[cfg(unix)]
    fn launched_plan_state(home: &ProbeLaunch) -> gateway::GatewayState {
        gateway::GatewayState {
            provider_registry: Some(home.registry.clone()),
            collaboration_chat_product_port: None,
            collaboration_presence_product_port: None,
            carrier_endpoint: None,
            collaboration_discovery_service: None,
            browser_internet: Default::default(),
            identity_manager: std::sync::Arc::new(std::sync::OnceLock::new()),
            cache_dir: home.data_dir.clone(),
            data_dir: home.data_dir.clone(),
        }
    }

    #[cfg(unix)]
    async fn stop_launched_agent(
        home: &ProbeLaunch,
        agent: &str,
    ) -> (StatusCode, serde_json::Value) {
        let response = stop_agent_session(
            axum::Extension(home.runtime.clone()),
            axum::Extension(home.audit_log.clone()),
            axum::body::Bytes::from(
                serde_json::to_vec(&serde_json::json!({"agent_id": agent})).unwrap(),
            ),
        )
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes)
                .unwrap_or(serde_json::json!(
                    String::from_utf8_lossy(&bytes).to_string()
                )),
        )
    }

    /// A10-R's mid-compute proof (S4). A spinning guest is resident beside a
    /// second agent. `DELETE` with a reason ends the spinning guest well
    /// before its own 10 s deadline: the entry is `stopped` with
    /// `stopped: <reason>` as its cause, one `Requested` stop is audited, and
    /// the entry is kept for its session. The other agent is untouched and
    /// completes.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancel_mid_compute() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let other_agent = home.agents[1].clone();
        let (spin_dir, spin_cid) = home.spin_host();
        let spinning = home.create_agent_for_host("spinning", &spin_cid);

        // The other agent launches first and is held in its own first call,
        // so its run spans the spinning guest's stop.
        let other = home.launch(&other_agent).await.unwrap().0;
        assert_eq!(other.status, "starting");
        home.wait_pending(&other.id).await;

        let run = home.launch_from(&spin_dir, &spinning).await.unwrap().0;
        assert_eq!(run.status, "starting");
        assert_eq!(run.session_id, run.id);
        let running = home.wait_running(&run.id).await;
        assert_eq!(running.status, "running");
        assert_eq!(running.principal.as_deref(), Some(spinning.as_str()));
        // `started` is published just before `run`, so the guest is spinning.
        let now = home.runtime.get_capsule(&run.id).await.expect("registered");
        assert_eq!(
            now.status, "running",
            "the spinning guest is still computing: cause={:?}",
            now.cause
        );

        // The stop's own bound: the guest's deadline is 10 s, so a stop that
        // takes five is a stop that did not interrupt the guest (F-notick).
        let asked = std::time::Instant::now();
        let (status, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stop_route(&home, &run.id, Some("spinning too long")),
        )
        .await
        .expect("the stop must end the spinning guest before its own deadline");
        assert_eq!(status, StatusCode::OK);
        assert!(
            asked.elapsed() < std::time::Duration::from_secs(5),
            "the stop took {:?}: the guest is still computing",
            asked.elapsed()
        );

        // The entry: stopped with the reason as its cause, its session kept.
        let entry = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("the ended entry is kept");
        assert_eq!(entry.status, "stopped");
        assert_eq!(entry.cause.as_deref(), Some("stopped: spinning too long"));
        assert!(entry.ended_at.is_some());
        assert_eq!(entry.session_id, run.id);
        let listed = home.listed().await;
        assert!(
            listed.iter().any(|entry| {
                entry["id"] == run.id
                    && entry["status"] == "stopped"
                    && entry["cause"] == "stopped: spinning too long"
            }),
            "the stopped entry is listed with its cause: {listed:?}"
        );

        // One stop audit, and it is the requested one, not an error.
        let stops: Vec<_> = home
            .audit_log
            .recent_events(usize::MAX)
            .into_iter()
            .filter_map(|event| match event {
                elastos_runtime::primitives::audit::AuditEvent::CapsuleStop {
                    capsule_id,
                    reason,
                    ..
                } if capsule_id == run.id => Some(reason),
                _ => None,
            })
            .collect();
        assert_eq!(stops.len(), 1, "exactly one stop audit: {stops:?}");
        assert!(
            matches!(
                stops[0],
                elastos_runtime::primitives::audit::StopReason::Requested
            ),
            "{stops:?}"
        );

        // Nothing of the activation is left to stop: a later stop answers
        // the recorded end.
        let (status, body) = stop_route(&home, &run.id, Some("again")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stop_answer(&body),
            ("stopped".into(), Some("stopped: spinning too long".into()))
        );

        // The other agent completes on its own calls.
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![other.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let end = home.wait_ended(&other.id).await;
        grants.abort();
        assert_eq!(end.status, "stopped");
        assert_eq!(end.cause.as_deref(), Some("completed"));
    }

    /// The route's optional body: a bodyless `DELETE` records the reason
    /// `user`, as the API's earlier stop did.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bodyless_stop_records_the_user_reason() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let (spin_dir, spin_cid) = home.spin_host();
        let spinning = home.create_agent_for_host("no-reason", &spin_cid);
        let run = home.launch_from(&spin_dir, &spinning).await.unwrap().0;
        assert_eq!(run.status, "starting");
        home.wait_running(&run.id).await;

        let (status, _) = stop_route(&home, &run.id, None).await;
        assert_eq!(status, StatusCode::OK);
        let entry = home.wait_ended(&run.id).await;
        assert_eq!(entry.status, "stopped");
        assert_eq!(entry.cause.as_deref(), Some("stopped: user"));
    }

    /// A10-R's mid-wait proof (S5). A's guest is inside its first bridge call,
    /// holding a capability request no shell answers. `DELETE` with a reason
    /// returns while that call is still waiting: the bridge's wait loop leaves
    /// it with `cancelled`, the activation ends `stopped` with the reason as
    /// its cause, and the request it was waiting on is denied by the Runtime
    /// with that cause. B, held in its own first call throughout, is
    /// untouched and then completes.
    #[cfg(unix)]
    #[tokio::test]
    async fn cancel_mid_wait() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents")
        };

        // Both agents launch and are held inside their own first bridge call:
        // the pending store is the observable edge of that.
        let run_a = home.launch(a).await.unwrap().0;
        assert_eq!(run_a.status, "starting");
        let a_pending = home.wait_pending(&run_a.id).await;
        let run_b = home.launch(b).await.unwrap().0;
        assert_eq!(run_b.status, "starting");
        let b_pending = home.wait_pending(&run_b.id).await;

        // DELETE while A's guest is inside that call. Its bridge wait is 30 s;
        // a stop that has to wait the call out has not interrupted it
        // (F-waitblind).
        let (status, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stop_route(&home, &run_a.id, Some("waiting too long")),
        )
        .await
        .expect("the stop must complete while the guest is inside its call: the request is still pending");
        assert_eq!(status, StatusCode::OK);

        let entry = home
            .runtime
            .get_capsule(&run_a.id)
            .await
            .expect("the ended entry is kept");
        assert_eq!(entry.status, "stopped");
        assert_eq!(entry.cause.as_deref(), Some("stopped: waiting too long"));

        // The request A's guest was waiting on is denied by the Runtime, with
        // the stop's cause.
        let settled = "instance ended: stopped: waiting too long";
        let after = home
            .pending_store
            .get_request(a_pending.id.as_str())
            .await
            .expect("the held request is still recorded");
        let elastos_runtime::capability::RequestStatus::Denied { reason, settled_by } =
            &after.status
        else {
            panic!(
                "the request the stopped guest was waiting on is not settled: {:?}",
                after.status
            );
        };
        assert_eq!(reason, settled);
        assert_eq!(*settled_by, elastos_runtime::capability::Settler::Runtime);

        // B's request was not settled by A's stop, and B still runs.
        assert!(
            home.pending_store
                .list_pending()
                .await
                .iter()
                .any(|request| request.id.as_str() == b_pending.id.as_str()),
            "A's stop settled no request of B's session"
        );
        assert_eq!(
            home.runtime
                .get_capsule(&run_b.id)
                .await
                .expect("B is still registered")
                .status,
            "running"
        );

        // B completes on its own calls.
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run_b.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let b_end = home.wait_ended(&run_b.id).await;
        grants.abort();
        assert_eq!(b_end.status, "stopped");
        assert_eq!(b_end.cause.as_deref(), Some("completed"));
    }

    /// A3-R S4+S5 fix 1 row. The guest spins in its start function: it is in
    /// guest code while the registry still says `starting`. `DELETE` with a
    /// reason ends it well before its own 10 s deadline and before its `run`:
    /// the entry is `stopped` with `stopped: <reason>`, kept, and one
    /// `Requested` stop is audited. A stop given to the provider only once
    /// the entry is `running` (F-startskip) leaves the start function to run
    /// to its own ending, which is then the entry's.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_during_start_ends_it_before_run() {
        use elastos_runtime::primitives::audit::StopReason;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let (dir, cid) = home.host_of("a5-spin-start-host", SPIN_START_COMPONENT);
        let agent = home.create_agent_for_host("spin-start", &cid);
        let run = home.launch_from(&dir, &agent).await.unwrap().0;
        assert_eq!(run.status, "starting");

        // The worker has taken the activation to run its start function: the
        // provider says `Running` while the registry still says `starting`.
        let started = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while home.runtime.component_status_for_test(&run.id).await
                != Some(elastos_common::CapsuleStatus::Running)
            {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            started.is_ok(),
            "the worker starts the guest: {:?} {:?}",
            home.runtime.component_status_for_test(&run.id).await,
            home.runtime.get_capsule(&run.id).await
        );
        let entry = home.runtime.get_capsule(&run.id).await.expect("registered");
        assert_eq!(entry.status, "starting", "{entry:?}");

        let asked = std::time::Instant::now();
        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stop_route(&home, &run.id, Some("stuck starting")),
        )
        .await
        .expect("the stop must end the start function before its own deadline");
        let took = asked.elapsed();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            stop_answer(&body),
            ("stopped".into(), Some("stopped: stuck starting".into()))
        );
        assert!(took < std::time::Duration::from_secs(5), "{took:?}");

        let entry = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("the ended entry is kept");
        assert_eq!(entry.status, "stopped");
        assert_eq!(entry.cause.as_deref(), Some("stopped: stuck starting"));
        assert!(entry.ended_at.is_some());
        let stops = stops_of(&home, &run.id);
        assert!(
            matches!(stops.as_slice(), [StopReason::Requested]),
            "{stops:?}"
        );
    }

    /// A3-R S4+S5 fix 2 row. A `DELETE` reads A's entry while A's end, which
    /// has settled and audited its trap, waits to record it. The activation's
    /// stop request is held until that end is recorded, so the stop leaves the
    /// entry to that end and answers it: `failed`, with the trap's cause. The
    /// entry is kept once, with that one cause, for the 60 s retention, and a
    /// later `DELETE` with another reason answers the same and removes
    /// nothing. A request taken away before the end is recorded (F-earlydrop)
    /// sends the stop down the launcher's path, which removes the entry.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_stop_racing_an_end_keeps_its_record_for_60_s() {
        use elastos_runtime::primitives::audit::StopReason;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let peer = point_at_peer(&home, a, b);
        let run = home.launch(a).await.unwrap().0;
        home.wait_pending(&run.id).await;
        home.wait_running(&run.id).await;

        // The registry is held: the stop's read of the entry waits first in
        // line, and A's end, which records last, waits behind it.
        let registry = home.runtime.hold_capsule_registry_for_test().await;
        let stopper = tokio::spawn(stop_capsule(
            Extension(home.runtime.clone()),
            Path(run.id.clone()),
            axum::body::Bytes::from_static(br#"{"reason":"racing the trap"}"#),
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run.id.clone()],
            Vec::new(),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while stops_of(&home, &run.id).is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("A traps and its end audits the stop");
        drop(registry);
        let (status, body) = answer_of(stopper.await.unwrap()).await;
        grants.abort();

        let end = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("the trap's record survives the racing stop");
        assert_eq!(end.status, "failed", "{end:?}");
        let cause = end.cause.clone().expect("a trap records its cause");
        assert!(cause.contains(SCOPE_REFUSAL), "{cause}");
        assert!(cause.contains(&peer), "{cause}");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(stop_answer(&body), ("failed".into(), Some(cause.clone())));
        let stops = stops_of(&home, &run.id);
        assert!(
            matches!(stops.as_slice(), [StopReason::Error(detail)] if detail == &cause),
            "one stop audit, the trap's: {stops:?}"
        );

        // A later stop answers the same end and removes nothing.
        let (status, again) = stop_route(&home, &run.id, Some("a later stop")).await;
        assert_eq!(status, StatusCode::OK, "{again}");
        assert_eq!(stop_answer(&again), stop_answer(&body));
        let after = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("a later stop removes nothing");
        assert_eq!(
            (&after.status, &after.cause, after.ended_at),
            (&end.status, &end.cause, end.ended_at)
        );
        assert_eq!(stops_of(&home, &run.id).len(), 1, "still one stop audit");

        // One entry, with its one cause, for the 60 s retention.
        let ended_at = end.ended_at.expect("the entry records its end");
        let within = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(59))
            .await;
        let kept: Vec<_> = within.iter().filter(|info| info.id == run.id).collect();
        assert_eq!(kept.len(), 1, "{within:?}");
        assert_eq!(kept[0].cause.as_deref(), Some(cause.as_str()));
        let past = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(60))
            .await;
        assert!(past.iter().all(|info| info.id != run.id), "{past:?}");
    }

    /// A3-R S4+S5 fix 3 row. A `DELETE` body that is not a stop request is
    /// refused with `400 invalid_stop_request`, and nothing is stopped:
    /// malformed JSON, an unknown field, a reason that is not a string, and
    /// text. The activation runs on with no stop recorded or audited. An
    /// empty body is still the stop with the reason `user`. A refused body
    /// read as no body (F-lenient) makes the first refusal a stop.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_malformed_stop_body_is_refused() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents[0].clone();
        let run = home.launch(&agent).await.unwrap().0;
        home.wait_pending(&run.id).await;

        let refused: [&[u8]; 4] = [
            br#"{"reason":"#,
            br#"{"why":"too long"}"#,
            br#"{"reason":5}"#,
            b"stop now",
        ];
        for body in refused {
            let (status, answer) = stop_route_with(&home, &run.id, body.to_vec()).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
            let answer: serde_json::Value = serde_json::from_str(&answer).expect("a JSON refusal");
            assert_eq!(answer["error"], "invalid_stop_request", "{answer}");
        }
        let entry = home.runtime.get_capsule(&run.id).await.expect("registered");
        assert!(entry.ended_at.is_none(), "nothing is stopped: {entry:?}");
        assert_eq!(home.runtime.requested_stop_for_test(&run.id), None);
        assert!(stops_of(&home, &run.id).is_empty());

        let (status, body) = stop_route_with(&home, &run.id, Vec::new()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            stop_answer(&body),
            ("stopped".into(), Some("stopped: user".into()))
        );
    }

    /// A3-R S4+S5 fix 4 row. A second stop arrives while the first is ending
    /// the activation: the first recorded cause is the one the end records,
    /// and both stops, and a third after the end, answer that one outcome.
    /// One stop is audited. (`runtime::tests::a_later_stop_keeps_the_first_cause`
    /// holds the rule itself.)
    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_stops_answer_the_first_recorded_cause() {
        use elastos_runtime::primitives::audit::StopReason;

        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents[0].clone();
        let run = home.launch(&agent).await.unwrap().0;
        home.wait_pending(&run.id).await;

        let first = tokio::spawn(stop_capsule(
            Extension(home.runtime.clone()),
            Path(run.id.clone()),
            axum::body::Bytes::from_static(br#"{"reason":"first"}"#),
        ));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let ended = home
                    .runtime
                    .get_capsule(&run.id)
                    .await
                    .is_some_and(|info| info.ended_at.is_some());
                if ended || home.runtime.requested_stop_for_test(&run.id).is_some() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the first stop records its cause");
        let second = stop_route(&home, &run.id, Some("second")).await;
        let first = answer_of(first.await.unwrap()).await;
        let third = stop_route(&home, &run.id, Some("third")).await;

        let outcome = ("stopped".to_string(), Some("stopped: first".to_string()));
        for (status, body) in [&first, &second, &third] {
            assert_eq!(*status, StatusCode::OK, "{body}");
            assert_eq!(stop_answer(body), outcome);
        }
        let entry = home.runtime.get_capsule(&run.id).await.expect("kept");
        assert_eq!((entry.status, entry.cause), outcome);
        let stops = stops_of(&home, &run.id);
        assert!(
            matches!(stops.as_slice(), [StopReason::Requested]),
            "{stops:?}"
        );
    }

    /// An ended entry is listed for the 60 s retention and is gone after it,
    /// read at a caller's instant rather than waited for.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_ended_entry_is_listed_for_sixty_seconds() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let answer = home.launch_with_grants(&agent).await.unwrap().0;
        let entry = home.wait_ended(&answer.id).await;
        let ended_at = entry.ended_at.expect("the entry records its end");

        // 59 s after the end the entry is still listed, with its session,
        // status and cause.
        let within = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(59))
            .await;
        assert_eq!(within.len(), 1, "{within:?}");
        assert_eq!(within[0].id, answer.id);
        assert_eq!(within[0].session_id, answer.id);
        assert_eq!(within[0].status, "stopped");
        assert_eq!(within[0].cause.as_deref(), Some("completed"));

        // At 61 s the same reading takes it away, and it stays away.
        let after = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(61))
            .await;
        assert!(after.is_empty(), "{after:?}");
        assert!(home.runtime.get_capsule(&answer.id).await.is_none());
    }

    /// What a start puts in place for an instance, before any end: the
    /// context the one end must clear. It is the Runtime's four tables, and the
    /// compute provider's activation entry and the principal it runs for. The
    /// principal is read here as well as after the end, so the after-row is not
    /// green because the start never bound one.
    #[cfg(unix)]
    async fn assert_context_filled(home: &ProbeLaunch, instance: &str, principal: &str) {
        let mut left = home.runtime.context_left_for_test(instance).await;
        left.sort_unstable();
        assert_eq!(
            left,
            ["manifest ceiling", "model-token ceiling", "stop request",],
            "the start filled {instance}'s context"
        );
        let handle = home
            .runtime
            .get_capsule(instance)
            .await
            .expect("the instance is registered while it runs")
            .handle
            .expect("a component launch keeps its handle");
        assert!(
            home.runtime.provider_entry_for_test(&handle).await,
            "the start left the provider an activation entry for {instance}"
        );
        assert_eq!(
            home.runtime.provider_principal_for_test(&handle).await,
            Some(Some(principal.to_string())),
            "the start bound {instance} to {principal}"
        );
    }

    /// A12-R at one ending: nothing of the instance remains. A late call from
    /// its id, carrying a token minted for exactly that call, is refused at
    /// the manifest (F-ctxleak leaves the ceiling and the call gets past the
    /// manifest and the grant check to the read); no grant of its session is
    /// live (F-norevoke keeps one); nothing of it waits for an answer; every
    /// record of its session is denied by the Runtime; the provider holds no
    /// entry for it; and its entry leaves the list once its 60 s have passed,
    /// read at an instant rather than waited for.
    #[cfg(unix)]
    async fn assert_nothing_remains(
        home: &ProbeLaunch,
        instance: &str,
        principal: &str,
        status: &str,
        cause: &str,
        seeded: (&str, &str),
    ) {
        use elastos_runtime::capability::{Action, ResourceId, TokenConstraints};
        // The late call first: it is what a leaked ceiling would still let
        // through. It is the context the installed host call builds for this
        // id, read from the Runtime's own tables, and a token minted now for
        // exactly this call: a malformed or absent token would refuse it
        // whatever the end left, so the answer below is the missing ceiling's.
        // The grant is revoked after the answer, so the views see the session
        // as the end left it.
        let tables = home.runtime.bridge_tables_for_test(instance);
        let late_uri = format!("{}/memory/notes.md", home.root(principal));
        let late_token = home.capability_manager.grant(
            instance,
            ResourceId::new(&late_uri),
            Action::Read,
            TokenConstraints::default(),
            None,
        );
        let line = serde_json::json!({
            "id": 31,
            "request": {
                "type": "resource_invoke",
                "uri": late_uri,
                "operation": "read",
                "token": late_token.to_base64().expect("a minted token is base64"),
                "body": {},
            }
        })
        .to_string();
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: home.registry.clone(),
            capability_manager: home.capability_manager.clone(),
            pending_store: home.pending_store.clone(),
            capsule_id: instance.to_string(),
            session_id: instance.to_string(),
            principal_id: Some(principal.to_string()),
            manifest_capabilities: tables.manifest_capabilities,
            data_dir: Some(home.data_dir.clone()),
            launch: tables.launch,
            model_token_ceiling: tables.model_token_ceiling,
            model_budget: None,
            stop: tables.stop,
            plan_book: None,
        };
        let answer = crate::resource_bridge::handle_component_resource_request(&line, ctx)
            .await
            .expect("the bridge answers a late call");
        assert_eq!(
            answer["response"]["code"], "manifest_capability_denied",
            "a late call from the ended instance {instance} must be refused: {answer}"
        );
        home.capability_manager
            .revoke(*late_token.id(), "the row's late call")
            .await
            .expect("the row's minted grant is revoked");

        // The all-sessions live grant view: no live grant of the instance.
        let live = home.live_view().await;
        assert!(
            !live.iter().any(|grant| grant["session_id"] == instance),
            "a live grant of {instance} remains: {live:?}"
        );

        // The pending view: nothing of the instance waits for an answer.
        let waiting = home.pending_view().await;
        assert!(
            !waiting
                .iter()
                .any(|request| request["session_id"] == instance),
            "a request of {instance} still waits: {waiting:?}"
        );

        // The request view: every record of the session is denied by the
        // Runtime, the two this row seeded among them.
        let records = home.request_view(instance).await;
        for record in &records {
            assert_eq!(record["status"], "denied", "{record}");
            assert_eq!(record["settled_by"], "runtime", "{record}");
        }
        for id in [seeded.0, seeded.1] {
            assert!(
                records.iter().any(|record| record["request_id"] == id),
                "the seeded request {id} left the store: {records:?}"
            );
        }

        // No ceiling, model-token ceiling, launch content or stop request of
        // the instance.
        let left = home.runtime.context_left_for_test(instance).await;
        assert!(left.is_empty(), "{instance} left {left:?} behind");

        // And no provider entry: nothing it could run or hand a call.
        let handle = home
            .runtime
            .get_capsule(instance)
            .await
            .expect("the ended entry keeps its handle")
            .handle
            .expect("a component launch keeps its handle");
        assert!(
            !home.runtime.provider_entry_for_test(&handle).await,
            "the provider still holds an activation entry for {instance}"
        );
        assert!(
            home.runtime
                .provider_principal_for_test(&handle)
                .await
                .is_none(),
            "the provider still holds the principal {instance} ran for"
        );

        // The entry: still listed 59 s after its end, gone at 61 s.
        let entry = home
            .runtime
            .get_capsule(instance)
            .await
            .expect("the ended entry is kept");
        assert_eq!(entry.status, status);
        assert_eq!(entry.cause.as_deref(), Some(cause));
        let ended_at = entry.ended_at.expect("the entry records its end");
        let within = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(59))
            .await;
        assert!(
            within.iter().any(|info| info.id == instance),
            "the entry is listed 59 s after its end: {within:?}"
        );
        let after = home
            .runtime
            .list_capsules_at(ended_at + std::time::Duration::from_secs(61))
            .await;
        assert!(
            !after.iter().any(|info| info.id == instance),
            "the entry is gone 61 s after its end: {after:?}"
        );
        assert!(home.runtime.get_capsule(instance).await.is_none());
        assert!(
            home.listed().await.is_empty(),
            "no entry of the ended instance is listed"
        );
    }

    /// A12-R after a stop (S4's ending). A spinning guest is stopped with a
    /// reason; the ask it was already granted is revoked, the one still
    /// pending is denied by the Runtime, its ceiling and provider entry are
    /// gone, a late call is refused, and its entry leaves the list at 60 s.
    #[cfg(unix)]
    #[tokio::test]
    async fn nothing_remains_after_stop() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let (spin_dir, spin_cid) = home.spin_host();
        let spinning = home.create_agent_for_host("spinning", &spin_cid);
        let run = home.launch_from(&spin_dir, &spinning).await.unwrap().0;
        assert_eq!(run.status, "starting");
        home.wait_running(&run.id).await;

        // What the bridge left in the instance's session, and what the start
        // put in place: the context the end must clear.
        let seeded = home.seed_session_requests(&run.id).await;
        assert!(
            home.live_view()
                .await
                .iter()
                .any(|grant| grant["session_id"] == run.id),
            "the seeded grant is live before the end"
        );
        assert!(
            home.pending_view()
                .await
                .iter()
                .any(|request| request["session_id"] == run.id),
            "the seeded ask waits before the end"
        );
        assert_context_filled(&home, &run.id, &spinning).await;

        let (status, _) = stop_route(&home, &run.id, Some("spinning too long")).await;
        assert_eq!(status, StatusCode::OK);

        assert_nothing_remains(
            &home,
            &run.id,
            &spinning,
            "stopped",
            "stopped: spinning too long",
            (seeded.0.as_str(), seeded.1.as_str()),
        )
        .await;
    }

    /// A12-R after a cancel (S5's ending). The guest is inside its first
    /// bridge call when `DELETE` arrives; the call is denied by the Runtime
    /// with the stop's cause, and the instance leaves no live grant, no
    /// pending request, no context or principal, no accepting late call and
    /// no entry after 60 s.
    #[cfg(unix)]
    #[tokio::test]
    async fn nothing_remains_after_cancel() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let run = home.launch(&agent).await.unwrap().0;
        assert_eq!(run.status, "starting");
        // The guest is inside its first bridge call, which no shell answers.
        let held = home.wait_pending(&run.id).await;
        let seeded = home.seed_session_requests(&run.id).await;
        assert_context_filled(&home, &run.id, &agent).await;

        let (status, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stop_route(&home, &run.id, Some("waiting too long")),
        )
        .await
        .expect("the stop must complete while the guest is inside its call");
        assert_eq!(status, StatusCode::OK);

        // The call the guest was waiting on is denied by the Runtime with the
        // stop's cause.
        let after = home
            .pending_store
            .get_request(held.id.as_str())
            .await
            .expect("the held request is still recorded");
        let elastos_runtime::capability::RequestStatus::Denied { reason, settled_by } =
            &after.status
        else {
            panic!("the held request is not settled: {:?}", after.status);
        };
        assert_eq!(reason, "instance ended: stopped: waiting too long");
        assert_eq!(*settled_by, elastos_runtime::capability::Settler::Runtime);

        assert_nothing_remains(
            &home,
            &run.id,
            &agent,
            "stopped",
            "stopped: waiting too long",
            (seeded.0.as_str(), seeded.1.as_str()),
        )
        .await;
    }

    /// A12-R after a failure (S3's ending). The guest traps on a refusal of
    /// another agent's stored root; the grants it had are revoked, the ask
    /// still pending is denied by the Runtime, the context and principal are
    /// gone, a late call is refused, and the entry leaves the list at 60 s.
    #[cfg(unix)]
    #[tokio::test]
    async fn nothing_remains_after_failure() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, b] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_a, root_b) = (home.root(a), home.root(b));
        let peer = format!("{root_b}/memory/notes.md");
        let pointer_uri = format!("{root_a}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            a,
            &root_a,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();

        let run = home.launch(a).await.unwrap().0;
        assert_eq!(run.status, "starting");
        let seeded = home.seed_session_requests(&run.id).await;
        assert_context_filled(&home, &run.id, a).await;

        // A's own calls are granted as the shell would grant them; the seeded
        // ask is held, so it stays pending until A's end.
        let grants = grant_requests_of(
            home.pending_store.clone(),
            home.capability_manager.clone(),
            vec![run.id.clone()],
            vec![SEEDED_REQUEST_RESOURCE.to_string()],
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let end = home.wait_ended(&run.id).await;
        grants.abort();
        assert_eq!(end.status, "failed");
        let cause = end.cause.clone().expect("a trap records its cause");

        assert_nothing_remains(
            &home,
            &run.id,
            a,
            "failed",
            &cause,
            (seeded.0.as_str(), seeded.1.as_str()),
        )
        .await;
    }

    /// Row 2, refusal: agent X's own guest asks for agent Y's file by Y's
    /// stored root. The bridge refuses the request, nothing under Y's root is
    /// read or audited for X, and X's activation ends `failed` with that
    /// refusal as its cause.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_guest_refuses_another_agents_stored_root() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());

        // Y's own guest writes Y's journal and notes under Y's stored root.
        let y_run = home.launch(y).await.unwrap().0;
        assert_eq!(y_run.status, "starting");
        let y_end = home.wait_ended(&y_run.id).await;
        assert_eq!(y_end.cause.as_deref(), Some("completed"));
        let (root_x, root_y) = (home.root(x), home.root(y));
        let peer = format!("{root_y}/memory/notes.md");

        // The pointer is test setup under X's own root, so X's guest learns
        // the URI it is asked to read. The guest's read of the pointer is a
        // bridge call like any other.
        let pointer_uri = format!("{root_x}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            x,
            &root_x,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();

        // The route admits X and answers at `starting`: the refusal is the
        // guest's, and it is recorded as the entry's cause.
        let run = home.launch(x).await.unwrap().0;
        assert_eq!(run.status, "starting");
        let end = home.wait_ended(&run.id).await;
        assert_eq!(end.status, "failed");
        let message = end.cause.clone().expect("a failed entry records its cause");
        assert!(
            message.contains(
                "localhost://UsersAI roots must use UsersAI/self or the active principal root"
            ),
            "{message}"
        );
        assert!(message.contains(&peer), "{message}");

        // X's own calls and the pointer read happened. The refused capability
        // request for Y's file is refused before any invoke, so no completed
        // call names it.
        let invoked = home.invoked(x);
        assert_eq!(invoked.len(), 5, "{invoked:?}");
        assert_eq!(
            invoked[4].2,
            format!("read {pointer_uri} owner={}", home.owner)
        );
        assert_eq!(invoked[4].1, "ok");
        assert!(
            invoked.iter().all(|(_, _, reason)| !reason.contains(&peer)),
            "no bridge call reached {peer}: {invoked:?}"
        );
        // Y's own guest wrote the file X was refused.
        assert!(home
            .invoked(y)
            .iter()
            .any(|(_, result, reason)| result == "ok"
                && reason == &format!("write {root_y}/memory/notes.md owner={}", home.owner)));
        grants.abort();
    }

    /// Row 7 (S5 part 2): an object the launched guest writes under its own
    /// root is an envelope on disk, and only the owner's stored key opens it.
    /// The activation ends only when the guest's own bridge read returns the
    /// bytes it wrote, so the read half is already proven by its end.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_guest_object_is_encrypted_and_needs_the_owners_key() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x"]).await;
        let [x] = home.agents.as_slice() else {
            panic!("one agent");
        };
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let run = home
            .launch(x)
            .await
            .unwrap_or_else(|err| panic!("the launch is admitted: {err:?}"))
            .0;
        assert_eq!(run.status, "starting");
        let end = home.wait_ended(&run.id).await;
        assert_eq!(end.status, "stopped");
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();

        let root = home.root(x);
        let notes = format!("{root}/memory/notes.md");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &notes).unwrap();

        // The row's at-rest claim: the object the guest wrote is an envelope on
        // disk, and the text it wrote appears nowhere in it. A production
        // change that stops the agent's own object from taking the protected
        // path leaves no encrypted object, and this assertion is where that
        // consequence shows.
        let bytes = std::fs::read(&path).unwrap_or_else(|err| {
            panic!("an agent's own object must be at rest as an encrypted envelope, never plaintext: {err}")
        });
        let envelope: serde_json::Value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("the agent's notes are not an envelope: {err}"));
        assert_eq!(envelope["schema"], "elastos.principal-root.object/v1");
        let plaintext = format!("a5-launch-probe notes for {x}");
        assert!(
            !String::from_utf8_lossy(&bytes).contains(&plaintext),
            "an agent's own object must be at rest as an encrypted envelope, never plaintext"
        );

        // The activation ended only after the guest's own bridge read returned
        // the bytes it wrote.
        assert!(home.invoked(x).iter().any(|(_, result, reason)| {
            result == "ok" && reason == &format!("read {notes} owner={}", home.owner)
        }));

        // The same object opens for its principal through the route's read.
        assert_eq!(
            crate::auth::read_principal_root_object(&home.data_dir, x, &root, &notes, &path)
                .unwrap(),
            plaintext.as_bytes()
        );

        // Without the owner's stored key the agent's read refuses by name.
        crate::auth::clear_test_principal_root_protections(&home.data_dir);
        assert_eq!(
            crate::auth::read_principal_root_object(&home.data_dir, x, &root, &notes, &path)
                .unwrap_err()
                .to_string(),
            "agent's owner holds no storage protection"
        );

        // A fresh owner key is not the one that wrapped this object.
        crate::auth::store_test_principal_root_protection(&home.data_dir, &home.owner);
        assert_eq!(
            crate::auth::read_principal_root_object(&home.data_dir, x, &root, &notes, &path)
                .unwrap_err()
                .to_string(),
            "principal-root decrypt failed"
        );
    }

    /// Row 3 (S5 part 2): the same spellings with the launched agent's own
    /// segment name its own root, so the bridge serves them. A bare own root
    /// stays beyond the probe host's `.../self/*` ceiling, and the traversal
    /// spellings stay outside the root. The capturing localhost double shows
    /// exactly which calls fell past the protected path.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_guest_serves_its_own_root_on_the_component_bridge() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let scope = "localhost://UsersAI roots must use UsersAI/self or the active principal root";
        let ceiling = "capsule manifest does not declare authority for ";
        let root = home.root(x);
        let segment = root.trim_start_matches("localhost://UsersAI/").to_string();
        let notes = format!("{root}/memory/notes.md");
        let memory = format!("{root}/memory");
        let doomed = format!("{root}/memory/doomed.txt");
        let own_text = "row 3 own notes";
        let upper = segment.to_uppercase();
        let mut plan = vec![
            format!("invoke\t{notes}\t{notes}\tread\tread\t"),
            format!("write\t{notes}\t{notes}\twrite\t{own_text}"),
            format!("invoke\t{notes}\t{notes}\tread\tread\t"),
            format!("invoke\t{memory}\t{memory}\tlist\tread\t"),
            format!("invoke\t{doomed}\t{doomed}\tdelete\tdelete\t"),
            format!("request\t{root}\tread"),
            format!("request\t{root}/\tread"),
            format!("request\t{root}/../{segment}\tread"),
            format!("request\tlocalhost://UsersAI/./{segment}\tread"),
            format!("request\tlocalhost://UsersAI//{segment}\tread"),
            format!("request\tlocalhost://UsersAI/%2e%2e%2f{segment}/memory/notes.md\tread"),
            format!("invoke\t{notes}\tlocalhost://UsersAI/self\tread\tread\t{notes}"),
            format!("invoke\t{notes}\t{notes}\tread\tread\t{notes}"),
        ];
        let mut upper_index = None;
        if upper != segment {
            upper_index = Some(plan.len());
            plan.push(format!("request\tlocalhost://UsersAI/{upper}\tread"));
        }

        let root_y = home.root(y);
        let y_dir =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &root_y).unwrap();
        let y_before = tree_hashes(&y_dir);

        home.plan(x, &plan);
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let run = home.launch(x).await.unwrap().0;
        assert_eq!(run.status, "starting");
        let end = home.wait_ended(&run.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();

        let results = home.results(x);
        assert_eq!(results.len(), plan.len(), "{results:?}");
        let at = |index: usize| {
            results
                .get(index)
                .cloned()
                .unwrap_or_else(|| panic!("no result for plan entry {index}: {results:?}"))
        };
        // A result line is `<index>\t<outcome>`; the outcome is what the
        // guest recorded for the entry.
        let outcome =
            |index: usize| -> String { at(index).split_once('\t').unwrap().1.to_string() };
        // A read's content is the byte array the bridge returns. Decode it so
        // the assertion is on the bytes, not their JSON spelling.
        let content = |index: usize| -> Vec<u8> {
            let line = outcome(index);
            let (status, json) = line.split_once(' ').unwrap();
            assert_eq!(status, "ok", "own-root cell {index}: {line}");
            let value: serde_json::Value = serde_json::from_str(json).unwrap();
            value["data"]["content"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as u8)
                .collect()
        };

        // S3': the own read returns the bytes the guest wrote, and the write
        // lands and reads back.
        assert!(
            String::from_utf8(content(0))
                .unwrap()
                .contains(&format!("a5-launch-probe notes for {x}")),
            "{}",
            at(0)
        );
        assert!(outcome(1).starts_with("ok"), "{}", at(1));
        assert_eq!(content(2), own_text.as_bytes());

        // List and delete are own-root operations the protected path does not
        // serve, so they reach the capturing provider.
        assert!(outcome(3).starts_with("ok"), "{}", at(3));
        assert!(outcome(4).starts_with("ok"), "{}", at(4));
        let requests = home.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert_eq!(requests[0]["path"], memory);
        assert_eq!(requests[0]["op"], "list");
        assert_eq!(requests[1]["path"], doomed);
        assert_eq!(requests[1]["op"], "delete");

        // A bare own root and its slash form are still beyond the ceiling.
        for index in [5, 6] {
            assert!(at(index).contains(ceiling), "{index}: {}", at(index));
        }
        // The `..` suffix is on no wildcard, even under the own prefix.
        assert!(at(7).contains(ceiling), "{}", at(7));
        // `.`, `//`, an upper-cased segment and an encoded traversal are not
        // the agent's stored root.
        for index in [8, 9, 10] {
            assert!(at(index).contains(scope), "{index}: {}", at(index));
        }
        if let Some(index) = upper_index {
            assert!(at(index).contains(scope), "{index}: {}", at(index));
        }

        // S10' and S11a': a URI and a body path that would name different
        // roots name this agent when the own segment is used, and are served.
        assert_eq!(content(11), own_text.as_bytes(), "{}", at(11));
        assert_eq!(content(12), own_text.as_bytes(), "{}", at(12));

        // The other agent's tree gained nothing.
        assert_eq!(tree_hashes(&y_dir), y_before);
    }

    /// Row A (S5 part 2, route 1 row 4): agent X's launched guest sends every
    /// bridge spelling of agent Y's stored root, for read, list, write and
    /// delete. Every Y-naming spelling is refused with the production
    /// sentence. The encoded traversal under X's own prefix stays inside X's
    /// root (the census's four held cells); its answer carries none of Y's
    /// data, and it neither lists nor changes Y's tree. The pending store and
    /// the capturing provider show that nothing reached Y on a refused cell.
    /// The bare area and its slash form (B4, B5) are junk spellings
    /// (definition:36): the ceiling refuses each, it creates no pending
    /// request, and it carries none of Y's data. Each bare spelling is also
    /// sent as the operation itself with X's held grant, and that answer
    /// carries none of Y's names, bytes or root segment either.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_guest_is_refused_every_other_spelling_of_another_agents_root() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_x, root_y) = (home.root(x), home.root(y));
        let seg_y = root_y.trim_start_matches("localhost://UsersAI/");
        let scope = "localhost://UsersAI roots must use UsersAI/self or the active principal root";
        let ceiling = "capsule manifest does not declare authority for ";
        let own_notes = format!("{root_x}/memory/notes.md");
        let y_notes = format!("{root_y}/memory/notes.md");
        let encoded = format!("{root_x}/%2e%2e%2f{seg_y}/memory/notes.md");
        let (canary_name, canary_text) = ("canary-do-not-leak", "y-agent canary bytes");

        // Y's root holds two protected objects before X's launch starts, so a
        // leak would have a name and bytes to show.
        for (name, text) in [
            (canary_name, canary_text),
            ("notes.md", "y-agent notes bytes"),
        ] {
            let uri = format!("{root_y}/memory/{name}");
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &uri).unwrap();
            crate::auth::write_principal_root_object(
                &home.data_dir,
                y,
                &root_y,
                &uri,
                &path,
                text.as_bytes(),
            )
            .unwrap();
        }
        let y_dir =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &root_y).unwrap();
        let y_before = tree_hashes(&y_dir);

        let mut lines: Vec<(String, String, PlanExpect)> = Vec::new();
        let mut refused_requests: Vec<String> = Vec::new();
        let mut cells = 0;
        for operation in ["read", "list", "write", "delete"] {
            let action = match operation {
                "read" | "list" => "read",
                "write" => "write",
                _ => "delete",
            };
            let spellings: Vec<(&str, String, PlanExpect)> = vec![
                ("S1", root_y.clone(), PlanExpect::Scope),
                ("S2", format!("{root_y}/"), PlanExpect::Scope),
                ("S3", y_notes.clone(), PlanExpect::Scope),
                ("S4", format!("{root_x}/../{seg_y}"), PlanExpect::Ceiling),
                (
                    "S5",
                    format!("localhost://UsersAI/./{seg_y}"),
                    PlanExpect::Scope,
                ),
                (
                    "S6",
                    format!("localhost://UsersAI//{seg_y}"),
                    PlanExpect::Scope,
                ),
                (
                    "S7",
                    format!("localhost://UsersAI/{}", seg_y.to_uppercase()),
                    PlanExpect::Scope,
                ),
                ("S8", encoded.clone(), PlanExpect::HeldRequest),
                (
                    "S9",
                    format!("localhost://UsersAI/%2e%2e%2f{seg_y}/memory/notes.md"),
                    PlanExpect::Scope,
                ),
                // B4 and B5: the two bare-area forms. They are junk spellings
                // (definition:36), normalized to `localhost://UsersAI`, so the
                // ceiling refuses them and nothing reaches Y.
                (
                    "B4",
                    "localhost://UsersAI".to_string(),
                    PlanExpect::BareArea,
                ),
                (
                    "B5",
                    "localhost://UsersAI/".to_string(),
                    PlanExpect::BareArea,
                ),
            ];
            for (id, resource, expect) in spellings {
                cells += 1;
                lines.push((
                    format!("{id} {operation} request"),
                    format!("request\t{resource}\t{action}"),
                    expect,
                ));
                if expect != PlanExpect::HeldRequest {
                    refused_requests.push(resource);
                }
            }
            // The held cell also asks the operation itself, so its answer can
            // be checked for Y's data. This line is not a second cell.
            lines.push((
                format!("S8 {operation} operation"),
                if operation == "write" {
                    format!("write\t{encoded}\t{encoded}\t{action}\tencoded write")
                } else {
                    format!("invoke\t{encoded}\t{encoded}\t{operation}\t{action}\t")
                },
                PlanExpect::HeldOperation,
            ));
            // B4 and B5 also ask the operation itself, addressed at the bare
            // spelling. The grant is X's own held notes, as in the S11 cells,
            // so the operation reaches the dispatch path instead of stopping
            // at the capability request. Like S8's, these lines are not cells.
            for (id, spelling) in [
                ("B4", "localhost://UsersAI"),
                ("B5", "localhost://UsersAI/"),
            ] {
                lines.push((
                    format!("{id} {operation} operation"),
                    if operation == "write" {
                        format!("write\t{own_notes}\t{spelling}\twrite\tbare-area write")
                    } else {
                        format!("invoke\t{own_notes}\t{spelling}\t{operation}\t{action}\t")
                    },
                    PlanExpect::BareAreaOperation,
                ));
            }
            for (id, uri, body) in [
                (
                    "S10",
                    "localhost://UsersAI/self".to_string(),
                    y_notes.clone(),
                ),
                ("S11a", y_notes.clone(), own_notes.clone()),
                ("S11b", own_notes.clone(), y_notes.clone()),
            ] {
                cells += 1;
                lines.push((
                    format!("{id} {operation}"),
                    format!("invoke\t{own_notes}\t{uri}\t{operation}\t{action}\t{body}"),
                    PlanExpect::Invalid,
                ));
            }
        }
        assert_eq!(cells, 56, "four operations over fourteen spellings");

        let plan: Vec<String> = lines.iter().map(|(_, line, _)| line.clone()).collect();
        home.plan(x, &plan);
        let run = home.launch_with_grants(x).await.unwrap().0;
        assert_eq!(run.status, "starting");
        assert_eq!(
            home.runtime
                .get_capsule(&run.id)
                .await
                .unwrap()
                .cause
                .as_deref(),
            Some("completed")
        );

        let results = home.results(x);
        assert_eq!(results.len(), lines.len(), "{results:?}");
        for (index, (label, line, expect)) in lines.iter().enumerate() {
            let outcome = plan_outcome(&results, index);
            match expect {
                PlanExpect::Scope => {
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(outcome.contains(scope), "{label}: {outcome}");
                }
                PlanExpect::Ceiling => {
                    let resource = line.split('\t').nth(1).unwrap();
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(outcome.contains(ceiling), "{label}: {outcome}");
                    assert!(outcome.contains(resource), "{label}: {outcome}");
                }
                PlanExpect::Invalid => {
                    assert!(outcome.contains("Invalid("), "{label}: {outcome}");
                    assert!(outcome.contains(scope), "{label}: {outcome}");
                }
                PlanExpect::HeldRequest => {
                    assert_eq!(outcome, "ok", "{label}: {outcome}");
                }
                PlanExpect::HeldOperation => {
                    assert!(!outcome.contains(canary_name), "{label}: {outcome}");
                    assert!(!outcome.contains(canary_text), "{label}: {outcome}");
                }
                PlanExpect::BareArea => {
                    // The junk clause first: no Y name, byte or root segment.
                    assert!(
                        !outcome.contains(canary_name),
                        "{label} reached Y: Y's canary name is in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(canary_text),
                        "{label} reached Y: Y's canary bytes are in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(seg_y),
                        "{label} reached Y: Y's root segment is in the answer: {outcome}"
                    );
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(
                        outcome.contains(
                            "capsule manifest does not declare authority for localhost://UsersAI"
                        ),
                        "{label}: {outcome}"
                    );
                }
                PlanExpect::BareAreaOperation => {
                    // The junk clause first: the operation at the bare spelling
                    // carries none of Y's names, bytes or root segment.
                    assert!(
                        !outcome.contains(canary_name),
                        "{label} reached Y: Y's canary name is in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(canary_text),
                        "{label} reached Y: Y's canary bytes are in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(seg_y),
                        "{label} reached Y: Y's root segment is in the answer: {outcome}"
                    );
                    // Then the refusal the census shows for the operation at
                    // this spelling: the manifest ceiling (resource_bridge.rs
                    // :636) with the sentence from manifest_denied_response
                    // (:554), written here independently of the request arm.
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(
                        outcome.contains(
                            "capsule manifest does not declare authority for localhost://UsersAI"
                        ),
                        "{label}: {outcome}"
                    );
                }
            }
        }
        // Every answer, refused or held, carries none of Y's bytes or names.
        for result in &results {
            assert!(!result.contains(canary_name), "{result}");
            assert!(!result.contains(canary_text), "{result}");
        }

        // No pending record survives, and a refused spelling never became one.
        assert!(home.pending_store.list_pending().await.is_empty());
        let requested = home.capability_requested();
        for resource in &refused_requests {
            assert!(
                !requested.iter().any(|recorded| recorded == resource),
                "a capability request record exists for {resource}: {requested:?}"
            );
        }
        // No capability-request record names Y's root. A record names it when
        // it is that root or a path under it; the held encoded spellings under
        // X's own root carry seg_y only inside a percent-encoded traversal, so
        // they are not Y's root and cannot reach it.
        assert!(
            !requested
                .iter()
                .any(|recorded| recorded == &root_y || recorded.starts_with(&format!("{root_y}/"))),
            "a capability request record names Y's root: {requested:?}"
        );
        // The provider saw only the two held cells the protected path does not
        // serve: list and delete of the encoded path under X's own root.
        let requests = home.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        for request in &requests {
            assert_eq!(request["path"], encoded);
        }
        assert_eq!(requests[0]["op"], "list");
        assert_eq!(requests[1]["op"], "delete");
        // No completed bridge call names Y's root.
        assert!(home
            .invoked(x)
            .iter()
            .all(|(_, _, reason)| !reason.contains(&root_y)));
        // Y's listing and hashes are identical before and after.
        assert_eq!(tree_hashes(&y_dir), y_before);
    }

    /// Row C (S5 part 2, route 18 row 4): the protected principal-root path
    /// serves read and write only, and the same fourteen spellings are refused
    /// for both. The encoded traversal under X's own prefix stays inside X's
    /// root (the census's two held cells). The launch's own journal and notes
    /// writes are the route's own-root control. A labelled unit companion then
    /// drives the protected path's root check with the agent id the launch
    /// admitted; it is not actor evidence, because the capability request that
    /// precedes every invoke refuses a foreign root before that check runs.
    /// The bare area and its slash form (B4, B5) are junk spellings
    /// (definition:36): the ceiling refuses each, it creates no pending
    /// request, and it carries none of Y's data. Each bare spelling is also
    /// sent as the operation itself with X's held grant, and that answer
    /// carries none of Y's names, bytes or root segment either.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agents_guest_cannot_reach_another_agents_root_on_the_protected_path() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_x, root_y) = (home.root(x), home.root(y));
        let seg_y = root_y.trim_start_matches("localhost://UsersAI/");
        let scope = "localhost://UsersAI roots must use UsersAI/self or the active principal root";
        let ceiling = "capsule manifest does not declare authority for ";
        let own_notes = format!("{root_x}/memory/notes.md");
        let y_notes = format!("{root_y}/memory/notes.md");
        let encoded = format!("{root_x}/%2e%2e%2f{seg_y}/memory/notes.md");
        let (canary_name, canary_text) = ("canary-do-not-leak", "y-agent canary bytes");

        for (name, text) in [
            (canary_name, canary_text),
            ("notes.md", "y-agent notes bytes"),
        ] {
            let uri = format!("{root_y}/memory/{name}");
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &uri).unwrap();
            crate::auth::write_principal_root_object(
                &home.data_dir,
                y,
                &root_y,
                &uri,
                &path,
                text.as_bytes(),
            )
            .unwrap();
        }
        let y_dir =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &root_y).unwrap();
        let y_before = tree_hashes(&y_dir);

        let mut lines: Vec<(String, String, PlanExpect)> = Vec::new();
        let mut refused_requests: Vec<String> = Vec::new();
        let mut cells = 0;
        for operation in ["read", "write"] {
            let spellings: Vec<(&str, String, PlanExpect)> = vec![
                ("S1", root_y.clone(), PlanExpect::Scope),
                ("S2", format!("{root_y}/"), PlanExpect::Scope),
                ("S3", y_notes.clone(), PlanExpect::Scope),
                ("S4", format!("{root_x}/../{seg_y}"), PlanExpect::Ceiling),
                (
                    "S5",
                    format!("localhost://UsersAI/./{seg_y}"),
                    PlanExpect::Scope,
                ),
                (
                    "S6",
                    format!("localhost://UsersAI//{seg_y}"),
                    PlanExpect::Scope,
                ),
                (
                    "S7",
                    format!("localhost://UsersAI/{}", seg_y.to_uppercase()),
                    PlanExpect::Scope,
                ),
                ("S8", encoded.clone(), PlanExpect::HeldRequest),
                (
                    "S9",
                    format!("localhost://UsersAI/%2e%2e%2f{seg_y}/memory/notes.md"),
                    PlanExpect::Scope,
                ),
                // B4 and B5: the two bare-area forms. They are junk spellings
                // (definition:36), normalized to `localhost://UsersAI`, so the
                // ceiling refuses them and nothing reaches Y.
                (
                    "B4",
                    "localhost://UsersAI".to_string(),
                    PlanExpect::BareArea,
                ),
                (
                    "B5",
                    "localhost://UsersAI/".to_string(),
                    PlanExpect::BareArea,
                ),
            ];
            for (id, resource, expect) in spellings {
                cells += 1;
                lines.push((
                    format!("{id} {operation} request"),
                    format!("request\t{resource}\t{operation}"),
                    expect,
                ));
                if expect != PlanExpect::HeldRequest {
                    refused_requests.push(resource);
                }
            }
            lines.push((
                format!("S8 {operation} operation"),
                if operation == "write" {
                    format!("write\t{encoded}\t{encoded}\twrite\tencoded write")
                } else {
                    format!("invoke\t{encoded}\t{encoded}\t{operation}\tread\t")
                },
                PlanExpect::HeldOperation,
            ));
            // B4 and B5 also ask the operation itself, addressed at the bare
            // spelling. The grant is X's own held notes, as in the S11 cells,
            // so the operation reaches the dispatch path instead of stopping
            // at the capability request. Like S8's, these lines are not cells.
            for (id, spelling) in [
                ("B4", "localhost://UsersAI"),
                ("B5", "localhost://UsersAI/"),
            ] {
                lines.push((
                    format!("{id} {operation} operation"),
                    if operation == "write" {
                        format!("write\t{own_notes}\t{spelling}\t{operation}\tbare-area write")
                    } else {
                        format!("invoke\t{own_notes}\t{spelling}\t{operation}\t{operation}\t")
                    },
                    PlanExpect::BareAreaOperation,
                ));
            }
            for (id, uri, body) in [
                (
                    "S10",
                    "localhost://UsersAI/self".to_string(),
                    y_notes.clone(),
                ),
                ("S11a", y_notes.clone(), own_notes.clone()),
                ("S11b", own_notes.clone(), y_notes.clone()),
            ] {
                cells += 1;
                lines.push((
                    format!("{id} {operation}"),
                    format!("invoke\t{own_notes}\t{uri}\t{operation}\t{operation}\t{body}"),
                    PlanExpect::Invalid,
                ));
            }
        }
        assert_eq!(cells, 28, "read and write over fourteen spellings");

        let plan: Vec<String> = lines.iter().map(|(_, line, _)| line.clone()).collect();
        home.plan(x, &plan);
        let run = home.launch_with_grants(x).await.unwrap().0;
        assert_eq!(run.status, "starting");
        assert_eq!(
            home.runtime
                .get_capsule(&run.id)
                .await
                .unwrap()
                .cause
                .as_deref(),
            Some("completed")
        );

        // The route's own-root control: the activation only ends after the
        // guest's own protected writes and reads return their bytes.
        assert!(home.invoked(x).iter().any(|(_, result, reason)| {
            result == "ok" && reason == &format!("write {own_notes} owner={}", home.owner)
        }));

        let results = home.results(x);
        assert_eq!(results.len(), lines.len(), "{results:?}");
        for (index, (label, line, expect)) in lines.iter().enumerate() {
            let outcome = plan_outcome(&results, index);
            match expect {
                PlanExpect::Scope => {
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(outcome.contains(scope), "{label}: {outcome}");
                }
                PlanExpect::Ceiling => {
                    let resource = line.split('\t').nth(1).unwrap();
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(outcome.contains(ceiling), "{label}: {outcome}");
                    assert!(outcome.contains(resource), "{label}: {outcome}");
                }
                PlanExpect::Invalid => {
                    assert!(outcome.contains("Invalid("), "{label}: {outcome}");
                    assert!(outcome.contains(scope), "{label}: {outcome}");
                }
                PlanExpect::HeldRequest => {
                    assert_eq!(outcome, "ok", "{label}: {outcome}");
                }
                PlanExpect::HeldOperation => {
                    assert!(!outcome.contains(canary_name), "{label}: {outcome}");
                    assert!(!outcome.contains(canary_text), "{label}: {outcome}");
                }
                PlanExpect::BareArea => {
                    // The junk clause first: no Y name, byte or root segment.
                    assert!(
                        !outcome.contains(canary_name),
                        "{label} reached Y: Y's canary name is in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(canary_text),
                        "{label} reached Y: Y's canary bytes are in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(seg_y),
                        "{label} reached Y: Y's root segment is in the answer: {outcome}"
                    );
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(
                        outcome.contains(
                            "capsule manifest does not declare authority for localhost://UsersAI"
                        ),
                        "{label}: {outcome}"
                    );
                }
                PlanExpect::BareAreaOperation => {
                    // The junk clause first: the operation at the bare spelling
                    // carries none of Y's names, bytes or root segment.
                    assert!(
                        !outcome.contains(canary_name),
                        "{label} reached Y: Y's canary name is in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(canary_text),
                        "{label} reached Y: Y's canary bytes are in the answer: {outcome}"
                    );
                    assert!(
                        !outcome.contains(seg_y),
                        "{label} reached Y: Y's root segment is in the answer: {outcome}"
                    );
                    // Then the refusal the census shows for the operation at
                    // this spelling: the manifest ceiling (resource_bridge.rs
                    // :636) with the sentence from manifest_denied_response
                    // (:554), written here independently of the request arm.
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(
                        outcome.contains(
                            "capsule manifest does not declare authority for localhost://UsersAI"
                        ),
                        "{label}: {outcome}"
                    );
                }
            }
        }
        for result in &results {
            assert!(!result.contains(canary_name), "{result}");
            assert!(!result.contains(canary_text), "{result}");
        }

        assert!(home.pending_store.list_pending().await.is_empty());
        let requested = home.capability_requested();
        for resource in &refused_requests {
            assert!(
                !requested.iter().any(|recorded| recorded == resource),
                "a capability request record exists for {resource}: {requested:?}"
            );
        }
        // No capability-request record names Y's root. A record names it when
        // it is that root or a path under it; the held encoded spellings under
        // X's own root carry seg_y only inside a percent-encoded traversal, so
        // they are not Y's root and cannot reach it.
        assert!(
            !requested
                .iter()
                .any(|recorded| recorded == &root_y || recorded.starts_with(&format!("{root_y}/"))),
            "a capability request record names Y's root: {requested:?}"
        );
        // Read and write both take the protected path, so no provider call is
        // made for any cell, held or refused.
        assert!(home.requests().is_empty(), "{:?}", home.requests());
        assert!(home
            .invoked(x)
            .iter()
            .all(|(_, _, reason)| !reason.contains(&root_y)));
        assert_eq!(tree_hashes(&y_dir), y_before);

        // Labelled unit companion, not actor evidence: the protected path's
        // own root check, driven with the id the launch admitted and a foreign
        // root. No launched guest can reach this check with Y's root, because
        // the capability request refuses the spelling first.
        let foreign = format!("{root_y}/memory/{canary_name}");
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
            capability_manager: home.capability_manager.clone(),
            pending_store: home.pending_store.clone(),
            capsule_id: "a5-s5-protected-path-companion".to_string(),
            session_id: "a5-s5-protected-path-companion".to_string(),
            principal_id: Some(x.clone()),
            manifest_capabilities: Vec::new(),
            data_dir: Some(home.data_dir.clone()),
            launch: None,
            model_token_ceiling: None,
            model_budget: None,
            stop: None,
            plan_book: None,
        };
        let request = serde_json::json!({"path": foreign, "content": "x"});
        let refused = crate::resource_bridge::protected_principal_root_resource_response_for_test(
            &ctx, "write", &request,
        )
        .unwrap();
        assert_eq!(
            refused["code"], "principal_context_required",
            "protected-path root check: {refused}"
        );
        assert_eq!(
            refused["message"],
            "localhost://Users roots must use Users/self or the active principal root",
            "protected-path root check: {refused}"
        );
    }

    /// The sentence the bridge uses when a rooted URI names anything but the
    /// caller's own stored root, on both the request and the invoke path.
    #[cfg(unix)]
    const A9R_SCOPE: &str =
        "localhost://UsersAI roots must use UsersAI/self or the active principal root";

    /// The three files A keeps under its own `UsersAI` root in the A9-R rows:
    /// the agent's format-2 journal, its `memory/notes.md`, and one ordinary
    /// file that is neither journal nor memory.
    #[cfg(unix)]
    fn a9r_own_uris(root: &str) -> (String, String, String) {
        (
            format!("{root}/.AppData/Agents/agent-host/tasks/t1/journal"),
            format!("{root}/memory/notes.md"),
            format!("{root}/notes/alpha.txt"),
        )
    }

    /// Writes A's three files the way production writes a principal-root
    /// object, so each has real bytes before either agent launches.
    #[cfg(unix)]
    fn a9r_place_own(home: &ProbeLaunch, agent: &str, root: &str, own: &(String, String, String)) {
        let mut journal = b"EAHJ".to_vec();
        journal.extend_from_slice(&2u16.to_le_bytes());
        journal.extend_from_slice(agent.as_bytes());
        let notes = format!("notes for {agent}");
        let foreign = b"alpha".to_vec();
        for (uri, content) in [
            (own.0.as_str(), journal),
            (own.1.as_str(), notes.into_bytes()),
            (own.2.as_str(), foreign),
        ] {
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, uri).unwrap();
            crate::auth::write_principal_root_object(
                &home.data_dir,
                agent,
                root,
                uri,
                &path,
                &content,
            )
            .unwrap();
        }
    }

    /// A9-R's fixture: one Home, two stored agents of its owner, each with its
    /// own `UsersAI` root, and the three files A keeps under its own root
    /// before either agent launches.
    #[cfg(unix)]
    struct A9rRow {
        home: ProbeLaunch,
        a: String,
        b: String,
        b_host: std::path::PathBuf,
        root_a: String,
        own: (String, String, String),
    }

    #[cfg(unix)]
    impl A9rRow {
        async fn new() -> Self {
            let home = ProbeLaunch::new(&["a"]).await;
            let [a] = home.agents.as_slice() else {
                panic!("one agent");
            };
            let a = a.clone();
            let root_a = home.root(&a);
            // Reuse the probe component. B's separately signed bundle names
            // A's bare root and its children, so the ceiling permits every
            // foreign-root cell before the principal-scope rule rejects it.
            let (b_host, b_cid) =
                home.host_with_claims("a9r-b-host", &[root_a.clone(), format!("{root_a}/*")]);
            let b = home.create_agent_for_host("b", &b_cid);
            let own = a9r_own_uris(&root_a);
            a9r_place_own(&home, &a, &root_a, &own);
            Self {
                home,
                a,
                b,
                b_host,
                root_a,
                own,
            }
        }
    }

    /// Grants B's requests under either agent root as the shell would. A's
    /// first request stays pending so A remains live throughout B's launch.
    #[cfg(unix)]
    fn grant_requests_under(
        store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        manager: Arc<elastos_runtime::capability::CapabilityManager>,
        roots: [String; 2],
        held_id: String,
    ) -> tokio::task::JoinHandle<()> {
        use elastos_runtime::capability::pending::GrantDuration;
        use elastos_runtime::capability::token::TokenConstraints;
        tokio::spawn(async move {
            let b_notes = format!("{}/memory/notes.md", roots[0]);
            loop {
                for pending in store.list_pending().await {
                    if pending.id.as_str() == held_id {
                        continue;
                    }
                    let resource = pending.resource.as_str();
                    if !roots
                        .iter()
                        .any(|root| resource == root || resource.starts_with(&format!("{root}/")))
                    {
                        continue;
                    }
                    // B asks for its own notes before each foreign invoke.
                    // Give that request a deliberately broad test grant: with
                    // valid token and manifest authority, only the principal
                    // scope can stop the foreign URI at dispatch.
                    let granted_resource = if resource == b_notes {
                        elastos_runtime::capability::ResourceId::new("localhost://UsersAI/*")
                    } else {
                        pending.resource.clone()
                    };
                    let token = manager.grant(
                        &pending.session_id.0,
                        granted_resource,
                        pending.action,
                        TokenConstraints::default(),
                        None,
                    );
                    let _ = store
                        .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                        .await;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
    }

    /// A9-R: two agents of one Home through the real Runtime, both live at the
    /// same time. A's activation is held inside its own first bridge call — its
    /// own journal grant, left pending — for the whole of B's launch, so A is a
    /// running instance with a live session when B's cells are refused. Only
    /// requests under B's own stored root are granted, which keeps A held; after
    /// B returns, A is released and must read its own three files back through
    /// the same bridge.
    ///
    /// B asks for `target` by the request path and the invoke path, for A's
    /// root as a listing, and once for its own alias as the control that the
    /// alias resolves to B's own root.
    #[cfg(unix)]
    async fn two_resident_agents_hold_a_while_b_is_refused(
        home: &ProbeLaunch,
        a: &str,
        b: &str,
        b_host: &std::path::Path,
        own: &(String, String, String),
        target: &str,
    ) -> (
        LaunchResponse,
        crate::runtime::RunningCapsuleInfo,
        LaunchResponse,
        crate::runtime::RunningCapsuleInfo,
        Vec<String>,
        Vec<(String, String, PlanExpect)>,
        elastos_runtime::capability::pending::PendingCapabilityRequest,
    ) {
        let root_a = home.root(a);
        let root_b = home.root(b);
        let b_notes = format!("{root_b}/memory/notes.md");
        let target = target.to_string();

        // A reads its own journal, notes and foreign file after its release.
        let a_plan: Vec<String> = [&own.0, &own.1, &own.2]
            .into_iter()
            .map(|uri| format!("invoke\t{uri}\t{uri}\tread\tread\t"))
            .collect();
        home.plan(a, &a_plan);

        let mut plan: Vec<(String, String, PlanExpect)> = Vec::new();
        for (id, operation, action) in [
            ("R1", "read", "read"),
            ("W1", "write", "write"),
            ("D1", "delete", "delete"),
        ] {
            plan.push((
                format!("{id} request"),
                format!("request\t{target}\t{action}"),
                PlanExpect::Scope,
            ));
            plan.push((
                format!("{id} invoke"),
                format!("invoke\t{b_notes}\t{target}\t{operation}\t{action}\t"),
                PlanExpect::Invalid,
            ));
        }
        // A bare-root list has no protected object-storage path. If the
        // invoke scope guard is removed, B's matching ceiling and broad test
        // grant carry this call all the way to the localhost provider. Keep
        // R1 request first so the request-scope plant fails at that grant.
        plan.insert(
            1,
            (
                "L1 invoke".to_string(),
                format!("invoke\t{b_notes}\t{root_a}\tlist\tread\t"),
                PlanExpect::Invalid,
            ),
        );
        plan.push((
            "L1 request".to_string(),
            format!("request\t{root_a}\tread"),
            PlanExpect::Scope,
        ));
        plan.push((
            "H1 request".to_string(),
            "request\tlocalhost://UsersAI/self/memory/notes.md\tread".to_string(),
            PlanExpect::HeldRequest,
        ));
        home.plan(
            b,
            &plan
                .iter()
                .map(|(_, line, _)| line.clone())
                .collect::<Vec<_>>(),
        );

        let a_dir =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &root_a).unwrap();
        let a_launch = home.launch(a);
        let b_work = async {
            // A is live and inside the bridge before B is launched.
            let a_first = tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if let Some(request) =
                        home.pending_store.list_pending().await.into_iter().next()
                    {
                        break request;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("A must ask for its own journal grant");
            assert_eq!(
                a_first.resource.as_str(),
                own.0.as_str(),
                "A's first bridge call is its own journal"
            );
            let a_before = tree_hashes(&a_dir);

            let grants = grant_requests_under(
                home.pending_store.clone(),
                home.capability_manager.clone(),
                [root_b.clone(), root_a.clone()],
                a_first.id.as_str().to_string(),
            );
            let b_run = home.launch_from(b_host, b).await;
            let b_id = b_run
                .as_ref()
                .expect("B's route admits its launch")
                .0
                .id
                .clone();
            let b_end = home.wait_ended(&b_id).await;

            // A is still the same activation, held in the same request, after
            // B's launch has returned.
            let still = home.pending_store.list_pending().await;
            assert!(
                still
                    .iter()
                    .any(|request| request.id.as_str() == a_first.id.as_str()),
                "A must still be held in its own first bridge call: {still:?}"
            );
            // B has ended while A remains held. Any pending record other than
            // A's held request came from a refused cell.
            assert!(
                still.iter().all(|request| request.id == a_first.id),
                "a refused cell became a pending record: {still:?}"
            );
            assert_eq!(tree_hashes(&a_dir), a_before, "B changed A's tree");
            grants.abort();
            let all =
                grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
            (a_first, b_run, b_end, all)
        };
        let (a_run, (a_first, b_run, b_end, all)) = tokio::join!(a_launch, b_work);
        let (a_run, b_run) = (
            a_run.expect("the A launch task does not panic").0,
            b_run.expect("the B launch task does not panic").0,
        );
        // Both routes answered at `starting` while their guests ran. Their
        // ends are the registry's: wait for both before reading what the
        // guests wrote.
        let a_end = home.wait_ended(&a_run.id).await;
        all.abort();
        (a_run, a_end, b_run, b_end, home.results(b), plan, a_first)
    }

    /// The clauses every A9-R row shares after both activations end: both
    /// routes answered at `starting`, both guests ran to `stopped`/`completed`,
    /// B's cells carry the production sentence, A read its own three, A's
    /// stored bytes are A's, nothing named A's root became a pending record,
    /// the provider was never called, and the two agents ran in two different
    /// sessions.
    #[cfg(unix)]
    async fn assert_a9r_denial(
        row: &A9rRow,
        a_end: &crate::runtime::RunningCapsuleInfo,
        b_run: &LaunchResponse,
        b_end: &crate::runtime::RunningCapsuleInfo,
        a_first: &elastos_runtime::capability::pending::PendingCapabilityRequest,
        results: &[String],
        plan: &[(String, String, PlanExpect)],
    ) {
        let (home, a, b, own) = (&row.home, row.a.as_str(), row.b.as_str(), &row.own);
        let root_a = row.root_a.as_str();
        assert_eq!(b_run.status, "starting");
        for end in [a_end, b_end] {
            assert_eq!(end.status, "stopped");
            assert_eq!(end.cause.as_deref(), Some("completed"));
        }
        let a_session = a_first.session_id.0.clone();
        assert_eq!(
            a_end.id, a_session,
            "A's launch is the session it asked from"
        );

        assert_eq!(results.len(), plan.len(), "{results:?}");
        for (index, (label, _, expect)) in plan.iter().enumerate() {
            let outcome = plan_outcome(results, index);
            match expect {
                PlanExpect::Scope => {
                    assert!(outcome.contains("Internal("), "{label}: {outcome}");
                    assert!(outcome.contains(A9R_SCOPE), "{label}: {outcome}");
                }
                PlanExpect::Invalid => {
                    assert!(outcome.contains("Invalid("), "{label}: {outcome}");
                    assert!(outcome.contains(A9R_SCOPE), "{label}: {outcome}");
                }
                PlanExpect::HeldRequest => assert_eq!(outcome, "ok", "{label}: {outcome}"),
                _ => panic!("{label}: unexpected cell kind"),
            }
        }

        // The control: A's own guest read its journal, its notes and its
        // foreign file back through the same bridge.
        let a_own = home.results(a);
        assert_eq!(a_own.len(), 3, "{a_own:?}");
        for (index, label) in ["journal", "notes", "foreign"].iter().enumerate() {
            assert!(
                plan_outcome(&a_own, index).starts_with("ok"),
                "A reads its own {label}: {a_own:?}"
            );
        }

        // A's stored bytes are A's: the format-2 journal names A, the notes are
        // the guest's text for A, and the foreign file is the one the test
        // placed and nobody wrote.
        let read = |uri: &str| {
            let path =
                elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, uri).unwrap();
            crate::auth::read_principal_root_object(&home.data_dir, a, root_a, uri, &path).unwrap()
        };
        let journal = read(&own.0);
        assert_eq!(&journal[..4], b"EAHJ", "format-2 journal");
        assert_eq!(journal[4..6], 2u16.to_le_bytes());
        assert_eq!(&journal[6..], a.as_bytes(), "the journal names A");
        assert_eq!(
            read(&own.1),
            format!("a5-launch-probe notes for {a}").into_bytes()
        );
        assert_eq!(read(&own.2), b"alpha".to_vec());

        // Two live instances, two sessions: A's calls carry A's session and
        // B's calls carry B's, and no completed call of either names A's root
        // other than A's own.
        let invoked_a = home.invoked(a);
        let invoked_b = home.invoked(b);
        assert!(!invoked_a.is_empty() && !invoked_b.is_empty());
        let b_session = b_run.id.clone();
        assert_ne!(a_session, b_session);
        assert!(
            invoked_a
                .iter()
                .all(|(session, _, _)| session.as_deref() == Some(a_session.as_str())),
            "{invoked_a:?}"
        );
        assert!(
            invoked_b
                .iter()
                .all(|(session, _, _)| session.as_deref() == Some(b_session.as_str())),
            "{invoked_b:?}"
        );
        assert!(
            invoked_b
                .iter()
                .all(|(_, _, reason)| !reason.contains(root_a)),
            "B reached A's root: {invoked_b:?}"
        );

        // No refused cell became a pending record, and none reached the
        // provider. B's listing cell named A's bare root, which no launched
        // guest ever asks for legitimately, so it can be checked by name.
        assert!(home.pending_store.list_pending().await.is_empty());
        let requested = home.capability_requested();
        assert!(
            !requested.iter().any(|resource| resource == root_a),
            "a capability request record names A's bare root: {requested:?}"
        );
        assert!(home.requests().is_empty(), "{:?}", home.requests());
    }

    /// A9-R clause one, ISO-journal: with both agents live, B is refused A's
    /// agent journal through the real Runtime, and A reads its own.
    #[cfg(unix)]
    #[tokio::test]
    async fn both_resident_b_is_refused_a_journal_and_a_reads_its_own() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let row = A9rRow::new().await;
        let (a_run, a_end, b_run, b_end, results, plan, a_first) =
            two_resident_agents_hold_a_while_b_is_refused(
                &row.home,
                &row.a,
                &row.b,
                &row.b_host,
                &row.own,
                &row.own.0,
            )
            .await;
        assert_eq!(a_run.status, "starting");
        assert_eq!(b_run.status, "starting");
        assert_eq!(
            a_end.cause.as_deref(),
            Some("completed"),
            "A finishes after its release"
        );
        assert_a9r_denial(&row, &a_end, &b_run, &b_end, &a_first, &results, &plan).await;
    }

    /// A9-R clause two, ISO-memory: with both agents live, B is refused A's
    /// `memory/notes.md`, and A reads its own.
    #[cfg(unix)]
    #[tokio::test]
    async fn both_resident_b_is_refused_a_memory_file_and_a_reads_its_own() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let row = A9rRow::new().await;
        let (a_run, a_end, b_run, b_end, results, plan, a_first) =
            two_resident_agents_hold_a_while_b_is_refused(
                &row.home,
                &row.a,
                &row.b,
                &row.b_host,
                &row.own,
                &row.own.1,
            )
            .await;
        assert_eq!(a_run.status, "starting");
        assert_eq!(b_run.status, "starting");
        assert_eq!(
            a_end.cause.as_deref(),
            Some("completed"),
            "A finishes after its release"
        );
        assert_a9r_denial(&row, &a_end, &b_run, &b_end, &a_first, &results, &plan).await;
    }

    /// A9-R clause three, ISO-foreign: with both agents live, B is refused a
    /// file of A's that is neither journal nor memory, and A reads its own.
    #[cfg(unix)]
    #[tokio::test]
    async fn both_resident_b_is_refused_a_foreign_file_and_a_reads_its_own() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let row = A9rRow::new().await;
        let (a_run, a_end, b_run, b_end, results, plan, a_first) =
            two_resident_agents_hold_a_while_b_is_refused(
                &row.home,
                &row.a,
                &row.b,
                &row.b_host,
                &row.own,
                &row.own.2,
            )
            .await;
        assert_eq!(a_run.status, "starting");
        assert_eq!(b_run.status, "starting");
        assert_eq!(
            a_end.cause.as_deref(),
            Some("completed"),
            "A finishes after its release"
        );
        assert_a9r_denial(&row, &a_end, &b_run, &b_end, &a_first, &results, &plan).await;
    }

    /// Row E (blocker evidence, no production change): a start that did not
    /// admit a stored agent refuses its principal by name before reading the
    /// folder. This is the attached start route that row 4's route 4 lacks.
    /// The folder declares no agent, so this row stops at the principal rule
    /// and not at the launcher rule.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_attached_start_refuses_a_stored_agents_principal() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x"]).await;
        let [x] = home.agents.as_slice() else {
            panic!("one agent");
        };
        let plain = crate::runtime::tests::write_fixture_capsule(
            &home.fixture_root,
            r#"{"schema":"elastos.capsule/v1","name":"attached-plain","version":"0.1.0","role":"app","type":"microvm","entrypoint":"rootfs.ext4"}"#,
        );
        let error = home
            .runtime
            .run_local_with_principal(
                &plain,
                Vec::new(),
                Some(crate::resource_bridge::BridgePrincipal::for_test(
                    x.as_str(),
                )),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            error,
            format!(
                "Invalid manifest: a stored agent's principal reaches only a launch that \
                 admitted it: {x}"
            )
        );
    }

    /// Row 1 refusal, round 2: the folder that would load names the stored
    /// Agent Host and writes the stored byte CID into its own `.elastos-cid`,
    /// but its entrypoint bytes are other code. Admission compares the walk of
    /// the folder with the CID the Runtime stored at creation, so the forged
    /// receipt decides nothing. Nothing is bound and no launch is audited.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agent_launch_refuses_a_forged_package_receipt() {
        use crate::agents;
        if crate::agents::require_build().is_err() {
            return;
        }
        use elastos_compute::providers::ComponentProvider;
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
        use elastos_storage::providers::LocalFSProvider;

        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let runtime = Arc::new(Runtime::with_providers_and_component(
            Arc::new(
                LocalFSProvider::new(temp.path().join("storage"))
                    .await
                    .unwrap(),
            ),
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let key = SigningKey::from_bytes(&[0x44; 32]);
        runtime
            .configure_capsule_admission(
                &data_dir,
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());

        let context =
            gateway::bind_device_session_grant(&data_dir, &[gateway::HOME_CAPSULE_ID, PROBE_HOST])
                .unwrap();
        let owner = context.principal_id().to_string();
        crate::auth::store_test_principal_root_protection(&data_dir, &owner);
        make_admin(&data_dir, &owner);
        let record = crate::auth::stored_principal_record(&data_dir, &owner)
            .unwrap()
            .unwrap();
        let caller = agents::Caller {
            principal_id: &owner,
            proof_binding_id: &record.proof_binding_id,
            session_id: "session:a5-host",
        };
        agents::set_enabled(&data_dir, &caller, true, 1).unwrap();
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components");
        let sign = |dir: &std::path::Path, entrypoint: &str, wasm: &[u8]| {
            let fixture = fixtures.join("a5-launch-probe/capsule.json");
            let mut manifest: elastos_common::CapsuleManifest =
                serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
            manifest.entrypoint = entrypoint.to_string();
            sign_capsule(&key, &mut manifest, &hash_content(wasm)).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            std::fs::write(dir.join(entrypoint), wasm).unwrap();
        };

        // The stored host: the probe's own bytes, named by the Runtime's walk.
        let stored_dir = temp.path().join(PROBE_HOST);
        std::fs::create_dir_all(&stored_dir).unwrap();
        sign(
            &stored_dir,
            "a5-launch-probe.component.wasm",
            &std::fs::read(fixtures.join("a5-launch-probe/a5-launch-probe.component.wasm"))
                .unwrap(),
        );
        std::fs::write(
            stored_dir.join(".elastos-cid"),
            format!("{PROBE_REGISTRY_CID}\n"),
        )
        .unwrap();
        let stored_cid =
            crate::stage_cmd::bundle_cid(&stored_dir).expect("the stored host is walkable");
        let agent = agents::create(
            &data_dir,
            &caller,
            &agents::CreateRequest {
                display_name: "a".to_string(),
                agent_host: PROBE_HOST.to_string(),
                request_id: "request-a".to_string(),
            },
            |host| {
                Ok(
                    crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                        host,
                        PROBE_REGISTRY_CID,
                        &stored_cid,
                    ),
                )
            },
            1,
        )
        .unwrap()
        .agent_id;
        agents::set_active(&data_dir, &caller, &agent, true, 1).unwrap();

        // The forged capsule: the stored manifest name and the stored CID in
        // its own `.elastos-cid`, signed by a trusted key, over other code.
        let forged_dir = temp.path().join("forged-probe");
        std::fs::create_dir_all(&forged_dir).unwrap();
        let other_wasm =
            std::fs::read(fixtures.join("bus-v1/bus-v1-conformance.component.wasm")).unwrap();
        sign(&forged_dir, "forged.component.wasm", &other_wasm);
        std::fs::write(forged_dir.join(".elastos-cid"), format!("{stored_cid}\n")).unwrap();
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &data_dir, &agent, PROBE_HOST, &context,
        )
        .unwrap();

        let response = launch_capsule(
            Extension(runtime),
            Extension(audit_log.clone()),
            Extension(Some(data_dir.clone())),
            Json(LaunchRequest {
                path: forged_dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: Some(grant),
                agent_id: Some(agent),
            }),
        )
        .await;
        let (status, message) = match response {
            Ok(_) => panic!("the forged capsule was admitted"),
            Err(error) => error,
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, crate::agent_admission::NOT_THE_STORED_HOST);
        assert!(
            audit_log.recent_events(2).is_empty(),
            "the runtime started nothing"
        );
        assert!(
            crate::auth::load_auth_state(&data_dir)
                .unwrap()
                .audit
                .iter()
                .all(|event| event.event_type != "component.invoke.completed"),
            "no principal was bound to a bridge call"
        );
    }

    /// Round 3, point 1: the launch grant is checked against the name of the
    /// one walked manifest, not against an earlier read of `capsule.json`.
    /// The stored host's own bytes are unchanged; a grant that names another
    /// capsule is refused before admission and before any principal binds.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agent_launch_refuses_a_grant_for_another_capsule() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let context =
            gateway::bind_device_session_grant(&home.data_dir, &["another-capsule"]).unwrap();
        let grant = gateway::issue_home_launch_token_with_context(
            &home.data_dir,
            "another-capsule",
            &context,
        )
        .unwrap();

        let response = launch_capsule(
            Extension(home.runtime.clone()),
            Extension(home.audit_log.clone()),
            Extension(Some(home.data_dir.clone())),
            Json(LaunchRequest {
                path: home.capsule_dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: Some(grant),
                agent_id: Some(agent),
            }),
        )
        .await;
        let (status, message) = match response {
            Ok(_) => panic!("a grant for another capsule admitted the stored host"),
            Err(error) => error,
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("not authorized"), "{message}");
        assert!(
            home.audit_log.recent_events(2).is_empty(),
            "the runtime started nothing"
        );
        assert!(
            crate::auth::load_auth_state(&home.data_dir)
                .unwrap()
                .audit
                .iter()
                .all(|event| event.event_type != "component.invoke.completed"),
            "no principal was bound to a bridge call"
        );
    }

    /// The route reaches the bundle signature check through its by-CID
    /// fallback for a staged slot. Three files fail it in the three ways it
    /// can: a signer key that does not decode, a signature that does not
    /// verify, and a signature by a key this Home does not trust. Each gives
    /// the one refusal, and each takes the same steps before it.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_route_refuses_three_slot_signature_failures_with_the_same_work() {
        use elastos_compute::providers::ComponentProvider;
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
        use elastos_storage::providers::LocalFSProvider;

        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let trusted = SigningKey::from_bytes(&[0x62; 32]);
        runtime
            .configure_capsule_admission(
                &data_dir,
                &[hex::encode(trusted.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());

        // One component folder this Home records no install for, signed by
        // the key it trusts.
        let name = "slot-signature-cases";
        let folder = temp.path().join(name);
        std::fs::create_dir_all(&folder).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/a5-launch-probe");
        let wasm = std::fs::read(fixture.join("a5-launch-probe.component.wasm")).unwrap();
        let mut manifest: elastos_common::CapsuleManifest =
            serde_json::from_slice(&std::fs::read(fixture.join("capsule.json")).unwrap()).unwrap();
        manifest.name = name.to_string();
        manifest.agent = None;
        manifest.capabilities = Vec::new();
        sign_capsule(&trusted, &mut manifest, &hash_content(&wasm)).unwrap();
        std::fs::write(
            folder.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(folder.join(&manifest.entrypoint), &wasm).unwrap();

        // The slot the fallback reads: the folder's own bytes, staged under
        // the CID this Home accepts.
        let cid = crate::stage_cmd::bundle_cid(&folder).expect("the folder is walkable");
        let slot_cid: elastos_bundle_identity::LabCid = cid.parse().expect("a CID");
        let staged = temp.path().join("staged.sig.json");
        std::fs::write(
            &staged,
            crate::bundle_admission::tests::signed(&cid, &trusted),
        )
        .unwrap();
        crate::stage_cmd::stage_bundle(&runtime, &data_dir, &folder, &staged)
            .await
            .expect("the slot stages");

        // The shell session's launch token for this folder's capsule.
        let context = gateway::bind_device_session_grant(&data_dir, &[name]).unwrap();
        let owner = context.principal_id().to_string();
        crate::auth::store_test_principal_root_protection(&data_dir, &owner);
        make_admin(&data_dir, &owner);
        let grant =
            gateway::issue_home_launch_token_with_context(&data_dir, name, &context).unwrap();

        let stranger = SigningKey::from_bytes(&[0x63; 32]);
        let by_trusted = crate::bundle_admission::tests::sign_by_hand(
            &trusted,
            crate::bundle_admission::BUNDLE_SIGNATURE_DOMAIN,
            &cid,
        );
        let by_stranger = crate::bundle_admission::tests::sign_by_hand(
            &stranger,
            crate::bundle_admission::BUNDLE_SIGNATURE_DOMAIN,
            &cid,
        );
        let cases = [
            (
                "a signer key that does not decode",
                crate::bundle_admission::tests::file_for(
                    &cid,
                    "did:key:not-a-canonical-key",
                    &by_trusted,
                ),
            ),
            (
                "a signature that does not verify",
                crate::bundle_admission::tests::file_for(
                    &cid,
                    &crate::bundle_admission::tests::did(&trusted.verifying_key()),
                    &by_stranger,
                ),
            ),
            (
                "a key the Home does not trust",
                crate::bundle_admission::tests::file_for(
                    &cid,
                    &crate::bundle_admission::tests::did(&stranger.verifying_key()),
                    &by_stranger,
                ),
            ),
        ];

        let signature_path = crate::bundle_admission::bundle_signature_path(&data_dir, &slot_cid);
        let mut refusals = Vec::new();
        let mut works = Vec::new();
        for (case, file) in &cases {
            std::fs::write(&signature_path, file).unwrap();
            let _ = crate::bundle_admission::tests::take_signature_check_work();
            let response = launch_capsule(
                Extension(runtime.clone()),
                Extension(audit_log.clone()),
                Extension(Some(data_dir.clone())),
                Json(LaunchRequest {
                    path: folder.to_string_lossy().into_owned(),
                    principal_id: None,
                    launch_grant: Some(grant.clone()),
                    agent_id: None,
                }),
            )
            .await;
            let (status, message) = match response {
                Ok(_) => panic!("{case}: the route started the folder"),
                Err(error) => error,
            };
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}");
            assert!(message.contains("is not installed"), "{case}: {message}");
            assert!(message.contains(&cid), "{case}: {message}");
            refusals.push(message);
            works.push(crate::bundle_admission::tests::take_signature_check_work());
        }
        assert_eq!(
            refusals[0], refusals[1],
            "the same refusal for the same folder"
        );
        assert_eq!(
            refusals[1], refusals[2],
            "the same refusal for the same folder"
        );
        let same_work: Vec<&'static str> = vec!["signer key", "signature check", "trust scan"];
        for (case, work) in cases.iter().map(|(case, _)| case).zip(&works) {
            assert_eq!(work, &same_work, "{case}: the signature check's steps");
        }
        assert!(runtime.list_capsules().await.is_empty(), "nothing started");
    }

    /// Round 3, point 3: a record written before the Runtime stored the Agent
    /// Host's byte CID still loads through the real strict parser, and every
    /// launch of it is refused by name. The missing CID is never re-derived
    /// from `.elastos-cid` or from the release record.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_older_agent_record_without_byte_identity_refuses_launch() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let path = crate::agents::agent_file_path(&home.data_dir).unwrap();
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for stored in file["agents"].as_array_mut().expect("agents") {
            stored["record"]["agent_host_package"]
                .as_object_mut()
                .expect("the record holds its Agent Host package")
                .remove("bundle_cid");
        }
        let bytes = serde_json::to_vec(&file).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        // The real strict parser accepts the older shape.
        crate::agents::parse_strict(&bytes)
            .expect("an older record parses as this Runtime writes it");
        let owner = gateway::local_home_launch_token_context(&home.data_dir)
            .unwrap()
            .principal_id()
            .to_string();
        let loaded = crate::agents::stored_agent(&home.data_dir, &owner, &agent)
            .expect("the older record still loads");
        assert!(loaded
            .record
            .agent_host_package
            .as_ref()
            .unwrap()
            .bundle_cid
            .is_empty());

        let response = home.launch(&agent).await;
        let (status, message) = match response {
            Ok(_) => panic!("an older record without byte identity launched"),
            Err(error) => error,
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, crate::agent_admission::NO_STORED_BYTES);
        assert!(
            home.audit_log.recent_events(2).is_empty(),
            "the runtime started nothing"
        );
    }

    /// Row 6a: a launch request that carries a kind is refused by its shape.
    #[test]
    fn a_launch_request_carrying_a_kind_is_refused() {
        let error =
            serde_json::from_str::<LaunchRequest>(r#"{"path":"a5-launch-probe","kind":"agent"}"#)
                .unwrap_err();
        assert!(
            error.to_string().contains("unknown field `kind`"),
            "{error}"
        );
        // The same shape without a kind is read, and names no agent.
        let request: LaunchRequest = serde_json::from_str(r#"{"path":"a5-launch-probe"}"#).unwrap();
        assert!(request.agent_id.is_none());
    }

    /// A capsule whose manifest does not declare an agent cannot be launched
    /// as one, whatever the request names or the person owns. With agents off
    /// the launch is refused before any folder is read, by name.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_capsule_that_does_not_declare_an_agent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "not-an-agent");
        let walked = crate::agent_admission::walk_launch(&capsule_dir).expect("the capsule walks");
        if !crate::agents::build_allows() {
            let error = admit_agent_launch(
                Some(dir.path()),
                walked,
                Some("person:local:a5-owner"),
                "agent:v2:cccccccccccccccccccccccccccccccc",
            )
            .unwrap_err();
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1, crate::agents::FEATURE_OFF);
            return;
        }
        // A Home whose owner has a stored agent, so the launch reaches the
        // manifest rule instead of stopping at the lookup.
        let home = ProbeLaunch::new(&["a"]).await;
        let context = gateway::local_home_launch_token_context(&home.data_dir).unwrap();
        let agent = home.agents.first().expect("one agent").clone();
        let error = admit_agent_launch(
            Some(home.data_dir.as_path()),
            walked,
            Some(context.principal_id()),
            &agent,
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            error.1,
            "this capsule does not declare an agent, so no stored agent runs it"
        );
    }

    /// An agent launch needs this Home's data directory before it looks
    /// anything up.
    #[test]
    fn an_agent_launch_without_a_data_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = dir.path().join("a5-launch-probe");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::json!({
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": "a5-launch-probe",
                "role": "app",
                "type": "wasm",
                "entrypoint": "main.wasm",
                "agent": {"kind": "agent"}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(capsule_dir.join("main.wasm"), b"entrypoint").unwrap();
        let walked = crate::agent_admission::walk_launch(&capsule_dir).expect("the capsule walks");
        let error = admit_agent_launch(
            None,
            walked,
            Some("person:local:a5-owner"),
            "agent:v2:cccccccccccccccccccccccccccccccc",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "an agent launch needs this Home's data directory");
    }

    /// Row 8: the record of a real bridge call from an admitted agent is the
    /// agent as actor (`principal_id`) and the person it acts for (the owner),
    /// named in the existing `reason` field as `owner=<id>`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bridge_call_from_an_admitted_agent_names_the_agent_and_its_owner() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());

        let run = home.launch(&agent).await.unwrap().0;
        assert_eq!(run.status, "starting");
        let end = home.wait_ended(&run.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();

        let root = home.root(&agent);
        let events: Vec<_> = crate::auth::load_auth_state(&home.data_dir)
            .unwrap()
            .audit
            .into_iter()
            .filter(|event| event.event_type == "component.invoke.completed")
            .filter(|event| event.principal_id.as_deref() == Some(agent.as_str()))
            .collect();
        assert_eq!(
            events.len(),
            6,
            "four own-root calls, the peer miss and the plan miss"
        );
        for event in &events {
            assert_eq!(
                event.principal_id.as_deref(),
                Some(agent.as_str()),
                "the actor is the admitted agent"
            );
            assert!(
                event.reason.contains(&root),
                "the record names the agent's own root: {}",
                event.reason
            );
            assert!(
                event.reason.ends_with(&format!(" owner={}", home.owner)),
                "the record names the person it acts for: {}",
                event.reason
            );
            assert_eq!(event.session_id.as_deref(), Some(run.id.as_str()));
        }
        grants.abort();
    }

    /// Row 5, entrance one: an agent-declaring capsule does not launch from
    /// `launch_capsule` without its launcher. A request that names the agent
    /// and holds no grant stops at admission; a request that names no agent
    /// stops at the start, because the manifest declares one.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agent_launch_without_a_grant_refuses_on_launch_capsule() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let launch = |agent_id: Option<String>| {
            launch_capsule(
                Extension(home.runtime.clone()),
                Extension(home.audit_log.clone()),
                Extension(Some(home.data_dir.clone())),
                Json(LaunchRequest {
                    path: home.capsule_dir.to_string_lossy().into_owned(),
                    principal_id: None,
                    launch_grant: None,
                    agent_id,
                }),
            )
        };

        // The id is named; no launcher is.
        let (status, message) = launch(Some(agent.clone())).await.map(|_| ()).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, crate::agent_admission::NO_LAUNCHER);

        // No id is named; the manifest still declares the agent.
        let (status, message) = launch(None).await.map(|_| ()).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            message,
            format!("Invalid manifest: {}", crate::agent_admission::NO_LAUNCHER)
        );

        assert!(
            home.audit_log.recent_events(4).is_empty(),
            "the runtime started nothing"
        );
        assert!(
            crate::auth::load_auth_state(&home.data_dir)
                .unwrap()
                .audit
                .iter()
                .all(|event| !event.event_type.starts_with("component.invoke.")),
            "no principal was bound to a bridge call"
        );
    }

    /// Row 5, entrance two: the attach route. `run_cmd` and `capsule_cmd`
    /// attach a component with `Runtime::run_local`, which has no launcher and
    /// no admission context, so a manifest that declares an agent is refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_component_attached_without_an_admitted_launch_refuses_an_agent_host() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let error = home
            .runtime
            .run_local(&home.capsule_dir, Vec::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("Invalid manifest: {}", crate::agent_admission::NO_LAUNCHER)
        );
        assert!(
            home.audit_log.recent_events(4).is_empty(),
            "the runtime started nothing"
        );
    }

    /// Row 5: unsigned. The same attach start of an unsigned copy of the Agent
    /// Host refuses by the signature rule before any launcher question, and
    /// nothing starts.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_unsigned_agent_host_refuses_the_attach_route_by_name() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let dir = home.fixture_root.join("unsigned-probe");
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/a5-launch-probe");
        for file in ["capsule.json", "a5-launch-probe.component.wasm"] {
            std::fs::copy(fixture.join(file), dir.join(file)).unwrap();
        }
        let manifest: elastos_common::CapsuleManifest =
            serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap();
        assert!(manifest.signature.is_none(), "the fixture is unsigned");

        let error = home
            .runtime
            .run_local(&dir, Vec::new())
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: Capsule 'a5-launch-probe' is unsigned; only a source or development Home with dev_mode = true runs unsigned capsules"
        );
        assert!(
            home.audit_log.recent_events(4).is_empty(),
            "the runtime started nothing"
        );
    }

    /// Row 5: an agent retired or unknown. A retired agent still holds its id
    /// and root; both spellings of "no such agent of yours" refuse the launch
    /// with the same literal, and nothing starts.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_retired_or_unknown_agent_refuses_its_launch() {
        use crate::agents;
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let [a, _b] = home.agents.as_slice() else {
            panic!("two agents");
        };

        // An id in the right shape that no record holds.
        let unknown = "agent:v2:ffffffffffffffffffffffffffffffff";
        let (status, message) = home.launch(unknown).await.map(|_| ()).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, "the caller owns no agent with that id");

        // A stored agent that was retired.
        let record = crate::auth::stored_principal_record(&home.data_dir, &home.owner)
            .unwrap()
            .unwrap();
        let caller = agents::Caller {
            principal_id: &home.owner,
            proof_binding_id: &record.proof_binding_id,
            session_id: "session:a5-launch",
        };
        agents::retire(&home.data_dir, &caller, a, 3).unwrap();
        let (status, message) = home.launch(a).await.map(|_| ()).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, "the caller owns no agent with that id");

        assert!(
            home.audit_log.recent_events(8).is_empty(),
            "the runtime started nothing"
        );
    }

    /// Row 5: the launcher is a stored person whose current protection is
    /// gone. The agent's data key cannot open, so admission refuses before
    /// anything starts and mints nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_agent_launch_refuses_an_owner_without_current_protection() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();

        let path = crate::auth::auth_state_path(&home.data_dir).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["principal_root_protections"]
            .as_array_mut()
            .expect("the owner holds a protection")
            .retain(|protection| protection["principal_id"] != serde_json::json!(home.owner));
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        crate::auth::invalidate_verified_auth_state_cache_for_test(&home.data_dir);

        let (status, message) = home.launch(&agent).await.map(|_| ()).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, "agent's owner holds no storage protection");
        assert!(
            home.audit_log.recent_events(4).is_empty(),
            "the runtime started nothing"
        );
    }

    /// Row 6, second half: a manifest claim that names another agent's root
    /// neither selects the actor nor moves its root. The actor is the id
    /// admission recorded, and every call names that agent's own root.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_manifest_claim_naming_another_agents_root_leaves_the_actors_id() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let b = home.agents.get(1).expect("the other agent").clone();
        let root_b = home.root(&b);

        let (claim_dir, claim_cid) =
            home.host_with_claims("claimed-probe", &[format!("{root_b}/memory/notes.md")]);
        let agent = home.create_agent_for_host("c", &claim_cid);
        let root = home.root(&agent);
        assert_ne!(root, root_b, "the claim names another agent's root");
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());

        // The claim names another agent's root; admission still binds the agent
        // the request names, so the launch is the stored agent's own.
        let run = match home.launch_from(&claim_dir, &agent).await {
            Ok(run) => run.0,
            Err((status, message)) => {
                panic!("the claim does not name the actor: {status} {message}")
            }
        };
        assert_eq!(run.status, "starting");
        let end = home.wait_ended(&run.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));

        // Every completed bridge call is the admitted actor, and the record is
        // the actor's id. The claim names another agent's root; the bridge
        // refuses that root, so the call is recorded as an error rather than
        // as a call for the other agent.
        let events: Vec<_> = crate::auth::load_auth_state(&home.data_dir)
            .unwrap()
            .audit
            .into_iter()
            .filter(|event| event.event_type == "component.invoke.completed")
            .filter(|event| event.principal_id.as_deref() == Some(agent.as_str()))
            .collect();
        assert_eq!(
            events.len(),
            6,
            "four own-root calls, the peer read and the plan miss"
        );
        let own = events
            .iter()
            .filter(|event| event.result == "ok" && event.reason.contains(&root))
            .count();
        assert_eq!(own, 4, "the guest's own root still works");
        assert!(
            events.iter().all(|event| !event.reason.contains(&root_b)),
            "the claim moves no call: {events:?}"
        );
        assert_eq!(
            events.iter().filter(|event| event.result != "ok").count(),
            2,
            "the absent peer pointer and the absent plan are the only failed calls: {events:?}"
        );
        grants.abort();
    }

    #[cfg(unix)]
    async fn admitted_model_agent(
        tokens: Option<u64>,
    ) -> (
        ProbeLaunch,
        std::path::PathBuf,
        String,
        Arc<CapturingModelProvider>,
    ) {
        let home = ProbeLaunch::new(&[]).await;
        let (dir, cid) = home.model_host("model-host", tokens);
        let agent = home.create_agent_for_host("model", &cid);
        let model = Arc::new(CapturingModelProvider::default());
        let registry = Arc::new(elastos_runtime::provider::ProviderRegistry::new());
        registry.register(model.clone()).await;
        registry.register(home.provider.clone()).await;
        home.runtime
            .set_provider_registry(
                registry,
                home.capability_manager.clone(),
                home.pending_store.clone(),
                home.data_dir.clone(),
            )
            .await;
        model.watch(home.runtime.clone());
        (home, dir, agent, model)
    }

    #[cfg(unix)]
    async fn ask_model(
        home: &ProbeLaunch,
        dir: &std::path::Path,
        agent: &str,
        asked: Option<u64>,
    ) -> String {
        let body = match asked {
            None => String::new(),
            Some(tokens) => format!("\",\"model_tokens\":{tokens},\"pad\":\""),
        };
        home.plan(
            agent,
            &[format!(
                "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t{body}"
            )],
        );
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let launched = home.launch_from(dir, agent).await.unwrap().0;
        assert_eq!(launched.status, "starting");
        let end = home.wait_ended(&launched.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();
        home.results(agent).join("\n")
    }

    #[cfg(unix)]
    fn model_create_line(home: &ProbeLaunch, agent: &str, request_id: &str, extra: &str) -> String {
        model_create_line_for(
            home,
            agent,
            request_id,
            "offer:fixture",
            "text.generate",
            extra,
        )
    }

    #[cfg(unix)]
    fn model_create_line_for(
        home: &ProbeLaunch,
        agent: &str,
        request_id: &str,
        offer_id: &str,
        operation: &str,
        extra: &str,
    ) -> String {
        let resource = crate::provider_resource::build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": offer_id}),
        )
        .unwrap();
        let body = format!(
            "{{\"offer_id\":\"{offer_id}\",\"operation\":\"{operation}\",\"input\":{{\"schema\":\"elastos.model.input.text/v1\",\"prompt\":\"hi with fixture padding\"}},\"request_id\":\"{request_id}\"{extra}}}"
        );
        let root = home.root(agent);
        let hash = hex::encode(elastos_runtime::signature::hash_content(body.as_bytes()));
        let body_uri = format!("{root}/memory/model-create-{hash}.json");
        let body_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &body_uri).unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            agent,
            &root,
            &body_uri,
            &body_path,
            body.as_bytes(),
        )
        .unwrap();
        format!("send\t{resource}\t{resource}\truns_create\texecute\t{body_uri}")
    }

    #[cfg(unix)]
    /// A `send` plan line for one run create whose input prompt is the task's
    /// own text, so the fixture's answer names the task it answers. The body
    /// file is written under the agent's own root, as
    /// [`Self::model_create_line_for`] does for its fixed prompt.
    fn task_create_line(home: &ProbeLaunch, agent: &str, request_id: &str, task: &str) -> String {
        let resource = crate::provider_resource::build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": "offer:fixture"}),
        )
        .unwrap();
        let body = format!(
            "{{\"offer_id\":\"offer:fixture\",\"operation\":\"text.generate\",\"input\":{{\"schema\":\"elastos.model.input.text/v1\",\"prompt\":\"{task}\"}},\"request_id\":\"{request_id}\"}}"
        );
        let root = home.root(agent);
        let hash = hex::encode(elastos_runtime::signature::hash_content(body.as_bytes()));
        let body_uri = format!("{root}/memory/model-create-{hash}.json");
        let body_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &body_uri).unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            agent,
            &root,
            &body_uri,
            &body_path,
            body.as_bytes(),
        )
        .unwrap();
        format!("send\t{resource}\t{resource}\truns_create\texecute\t{body_uri}")
    }

    #[cfg(unix)]
    async fn run_model_plan(
        home: &ProbeLaunch,
        dir: &std::path::Path,
        agent: &str,
        creates: &[(&str, &str)],
    ) -> String {
        let mut lines = vec![
            "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t"
                .to_string(),
        ];
        lines.extend(
            creates
                .iter()
                .map(|(id, extra)| model_create_line(home, agent, id, extra)),
        );
        run_model_lines(home, dir, agent, &lines).await
    }

    #[cfg(unix)]
    async fn run_model_lines(
        home: &ProbeLaunch,
        dir: &std::path::Path,
        agent: &str,
        lines: &[String],
    ) -> String {
        home.plan(agent, lines);
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let launched = home.launch_from(dir, agent).await.unwrap().0;
        assert_eq!(launched.status, "starting");
        let end = home.wait_ended(&launched.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();
        home.results(agent).join("\n")
    }

    #[cfg(unix)]
    fn create_calls(model: &CapturingModelProvider) -> Vec<serde_json::Value> {
        model
            .requests()
            .into_iter()
            .filter(|request| request["op"] == "runs_create")
            .collect()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn over_cap_refused_before_dispatch() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let outcome = run_model_plan(
            &home,
            &dir,
            &agent,
            &[("request:first", ""), ("request:second", "")],
        )
        .await;
        assert_eq!(
            create_calls(&model).len(),
            1,
            "only the reserved run reaches Runtime dispatch"
        );
        assert!(outcome.contains("model_budget_exceeded"), "{outcome}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn resident_create_after_launch_returns_is_reserved() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        home.plan(
            &agent,
            &[
                "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t"
                    .into(),
                model_create_line(&home, &agent, "request:resident-first", ""),
                model_create_line(&home, &agent, "request:resident-second", ""),
            ],
        );
        let launched = home.launch_from(&dir, &agent).await.unwrap().0;
        assert_eq!(launched.status, "starting");
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let end = home.wait_ended(&launched.id).await;
        grants.abort();
        assert_eq!(end.cause.as_deref(), Some("completed"));
        let outcome = home.results(&agent).join("\n");
        assert!(outcome.contains("model_budget_exceeded"), "{outcome}");
        assert_eq!(create_calls(&model).len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retry_not_double_charged() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let outcome = run_model_plan(
            &home,
            &dir,
            &agent,
            &[
                ("request:retry", ""),
                ("request:retry", ""),
                ("request:new", ""),
            ],
        )
        .await;
        assert!(outcome.contains("model_budget_exceeded"), "{outcome}");
        let calls = create_calls(&model);
        assert_eq!(calls.len(), 2, "same request id reuses its hold");
        assert_eq!(
            calls[0]["runtime_binding"]["request_id"],
            calls[1]["runtime_binding"]["request_id"]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn changed_offer_retry_refused_before_dispatch() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let lines = vec![
            "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t".into(),
            model_create_line_for(
                &home,
                &agent,
                "request:swap",
                "offer:fixture",
                "wrong.operation",
                "",
            ),
            model_create_line_for(
                &home,
                &agent,
                "request:swap",
                "offer:large",
                "text.generate",
                "",
            ),
        ];
        let outcome = run_model_lines(&home, &dir, &agent, &lines).await;
        assert!(
            outcome.contains("Provider operation failed"),
            "first create must fail at provider: {outcome}"
        );
        let calls = create_calls(&model);
        assert_eq!(
            calls.len(),
            1,
            "the large offer must be refused before dispatch"
        );
        assert!(
            outcome.contains("request_id conflicts with an existing model hold"),
            "{outcome}"
        );
        assert_eq!(calls[0]["offer_id"], "offer:fixture");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn changed_revision_retry_refused_before_dispatch() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        model.raise_revision_after_rejection();
        let create = model_create_line(&home, &agent, "request:revision", "");
        let lines = vec![
            "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t".into(),
            create.clone(),
            "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t".into(),
            create,
        ];
        let retry = run_model_lines(&home, &dir, &agent, &lines).await;
        assert!(retry.contains("Provider operation failed"), "{retry}");
        assert!(
            retry.contains("request_id conflicts with an existing model hold"),
            "{retry}"
        );
        let calls = create_calls(&model);
        assert_eq!(
            calls.len(),
            1,
            "changed revision must be refused before dispatch"
        );
        assert_eq!(calls[0]["operation"], "text.generate");
        assert_eq!(
            calls[0]["expected_execution_binding_hash"],
            "sha256:fixture"
        );
        assert_eq!(
            model
                .requests()
                .iter()
                .filter(|request| request["op"] == "offers_list")
                .count(),
            2,
            "the retry must follow a fresh offer listing"
        );
    }

    /// One create through the bridge, as a session that did not Start. The
    /// account is the one [`crate::runtime::Runtime::model_dispatch_for_test`]
    /// reads for `session`, which is the live run's agent account when the
    /// caller has shared it.
    #[cfg(unix)]
    async fn invoke_shared_account_create(home: &ProbeLaunch, agent: &str, session: &str) {
        use elastos_runtime::capability::{Action, ResourceId, TokenConstraints};
        let resource = crate::provider_resource::build_capability_resource(
            "model",
            "runs_create",
            &serde_json::json!({"offer_id": "offer:fixture"}),
        )
        .unwrap();
        let token = home.capability_manager.grant(
            session,
            ResourceId::new(&resource),
            Action::Execute,
            TokenConstraints::default(),
            None,
        );
        let line = serde_json::json!({
            "id": 71,
            "request": {
                "type": "resource_invoke",
                "uri": resource,
                "operation": "runs_create",
                "token": token.to_base64().expect("a minted token is base64"),
                "body": {
                    "offer_id": "offer:fixture",
                    "operation": "text.generate",
                    "input": {
                        "schema": "elastos.model.input.text/v1",
                        "prompt": "hi with fixture padding"
                    },
                    "request_id": "request:concurrent"
                },
            }
        })
        .to_string();
        let ctx = home
            .runtime
            .bridge_context_for_test(session, Some(agent.to_string()))
            .await;
        crate::resource_bridge::handle_component_resource_request(&line, ctx)
            .await
            .expect("the planted session's create reaches the bridge");
        home.capability_manager
            .revoke(*token.id(), "planted model create")
            .await
            .expect("the planted create grant is revoked");
    }

    /// Two creates at one moment share one agent's ceiling. The second create
    /// is a planted session of that agent and did not go through Start. A
    /// second Start while the run is live is refused. After the run ends, a
    /// later Start is admitted and completes without another create.
    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_creates_share_cap() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let _ = ask_model(&home, &dir, &agent, None).await;
        home.plan(
            &agent,
            &[model_create_line(&home, &agent, "request:concurrent", "")],
        );
        let planted = "planted-model-session";
        home.runtime
            .register_capsule(crate::runtime::RunningCapsuleInfo {
                id: planted.to_string(),
                name: "planted".to_string(),
                status: "running".to_string(),
                capsule_type: elastos_common::CapsuleType::Wasm,
                handle: None,
                session_id: planted.to_string(),
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
                launch_id: "launch:planted-model-session".into(),
                session_id: planted.to_string(),
            })
            .await;
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let first = home.launch_from(&dir, &agent).await.unwrap().0;
        assert_eq!(first.status, "starting");
        home.runtime
            .share_agent_model_account_for_test(&first.id, planted);
        let planted_create = invoke_shared_account_create(&home, &agent, planted);
        let refused = home.launch_from(&dir, &agent);
        let (_planted_create, refused) = tokio::join!(planted_create, refused);
        let (code, body) = match refused {
            Err(err) => err,
            Ok(_) => panic!("the second Start was admitted"),
        };
        assert!(code == StatusCode::CONFLICT && body == "this agent is already running");
        assert_eq!(
            home.wait_ended(&first.id).await.cause.as_deref(),
            Some("completed")
        );
        home.plan(&agent, &[]);
        let second = home.launch_from(&dir, &agent).await.unwrap().0;
        assert_eq!(second.status, "starting");
        assert_eq!(
            home.wait_ended(&second.id).await.cause.as_deref(),
            Some("completed")
        );
        grants.abort();
        assert_eq!(
            create_calls(&model).len(),
            1,
            "two creates share the admitted agent ceiling"
        );
        let run_events: Vec<_> = crate::auth::load_auth_state(&home.data_dir)
            .unwrap()
            .audit
            .into_iter()
            .filter(|event| event.event_type == "component.invoke.completed")
            .filter(|event| event.principal_id.as_deref() == Some(agent.as_str()))
            .filter(|event| event.reason.contains("elastos://model/offers/sha256/"))
            .collect();
        assert_eq!(run_events.len(), 2, "both creates reached the bridge");
        assert_eq!(
            run_events
                .iter()
                .filter(|event| event.result == "denied")
                .count(),
            1,
            "the shared account refused one create"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn b_unaffected_by_a_exhaustion() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (dir, cid) = home.model_host("model-host", Some(1_140));
        let a = home.create_agent_for_host("model-a", &cid);
        let b = home.create_agent_for_host("model-b", &cid);
        let model = Arc::new(CapturingModelProvider::default());
        let registry = Arc::new(elastos_runtime::provider::ProviderRegistry::new());
        registry.register(model.clone()).await;
        registry.register(home.provider.clone()).await;
        home.runtime
            .set_provider_registry(
                registry,
                home.capability_manager.clone(),
                home.pending_store.clone(),
                home.data_dir.clone(),
            )
            .await;
        model.watch(home.runtime.clone());
        let a_outcome =
            run_model_plan(&home, &dir, &a, &[("request:a1", ""), ("request:a2", "")]).await;
        assert!(a_outcome.contains("model_budget_exceeded"), "{a_outcome}");
        let b_outcome = run_model_plan(&home, &dir, &b, &[("request:b1", "")]).await;
        assert!(!b_outcome.contains("model_budget_exceeded"), "{b_outcome}");
        let calls = create_calls(&model);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["runtime_binding"]["principal_id"], a);
        assert_eq!(calls[1]["runtime_binding"]["principal_id"], b);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn guest_cannot_raise_cap() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let forged = ",\"model_tokens\":999999999";
        let outcome = run_model_plan(
            &home,
            &dir,
            &agent,
            &[("request:guest1", forged), ("request:guest2", forged)],
        )
        .await;
        assert!(
            outcome.contains("unknown field `model_tokens`"),
            "{outcome}"
        );
        let calls = create_calls(&model);
        assert!(
            calls.is_empty(),
            "the unknown field is refused before dispatch"
        );
    }

    /// An admitted agent whose signed manifest asks for no model tokens cannot
    /// reach the model. The provider records no call.
    #[cfg(unix)]
    #[tokio::test]
    async fn no_ask_no_model() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(None).await;
        let outcome = ask_model(&home, &dir, &agent, None).await;
        assert!(
            outcome.contains("model_budget_exceeded: signed ceiling is 0"),
            "{outcome}"
        );
        assert!(model.requests().is_empty(), "{:?}", model.requests());
    }

    /// The ceiling the bridge holds for this instance is the signed one, after
    /// the guest sends a body that names a different ceiling. This row was
    /// `guest_cannot_raise_cap`. That name no longer fits: N9 does not refuse
    /// a larger ask. The body here names 0, which would refuse the call if the
    /// decision read it. The call still reaches the provider, and the Runtime
    /// map still holds the signed ceiling.
    #[cfg(unix)]
    #[tokio::test]
    async fn bridge_holds_signed_ceiling() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let signed = 16;
        let (home, dir, agent, model) = admitted_model_agent(Some(signed)).await;
        let outcome = ask_model(&home, &dir, &agent, Some(0)).await;
        assert!(
            !outcome.contains("model_budget_exceeded"),
            "a guest field is not the ceiling: {outcome}"
        );
        assert_eq!(model.requests().len(), 1, "{:?}", model.requests());
        assert_eq!(
            model.requests()[0]["model_tokens"],
            serde_json::json!(0),
            "the guest body reached the provider: {:?}",
            model.requests()
        );
        let held = model.ceilings_at_call();
        assert_eq!(
            held.len(),
            1,
            "the model call ran while the instance was up: {held:?}"
        );
        assert_eq!(
            held[0]
                .iter()
                .map(|(_, ceiling)| *ceiling)
                .collect::<Vec<_>>(),
            vec![signed],
            "the bridge holds the signed ceiling: {held:?}"
        );
        assert!(
            home.runtime.model_token_ceilings_held().is_empty(),
            "the held value was read during the call"
        );
    }

    /// An admitted agent with a positive signed ceiling reaches the model.
    /// The provider records one call.
    #[cfg(unix)]
    #[tokio::test]
    async fn positive_ceiling_reaches_model() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(16)).await;
        let outcome = ask_model(&home, &dir, &agent, None).await;
        assert!(!outcome.contains("model_budget_exceeded"), "{outcome}");
        assert_eq!(model.requests().len(), 1, "{:?}", model.requests());
        assert_eq!(model.requests()[0]["op"], "offers_list");
    }

    /// A plan's `send` line reads the body file the host wrote under the
    /// agent's own root and sends its bytes as the request body: the provider
    /// records the file's own object and only the Runtime's `op`. The `invoke`
    /// line beside it still sends `{"path": …}`, so the wrapper the fixture
    /// has always sent is unchanged.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_plan_send_line_sends_the_body_files_own_bytes() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(16)).await;
        let root = home.root(&agent);
        let body_uri = format!("{root}/memory/body.json");
        let body_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &body_uri).unwrap();
        let body = r#"{"model_tokens":3,"pad":"send body ✓ 𝄞","task":{"text":"name it"}}"#;
        crate::auth::write_principal_root_object(
            &home.data_dir,
            &agent,
            &root,
            &body_uri,
            &body_path,
            body.as_bytes(),
        )
        .unwrap();

        let offers = "elastos://model/offers";
        home.plan(
            &agent,
            &[
                format!("invoke\t{offers}\t{offers}\toffers_list\tread\t{body_uri}"),
                format!("send\t{offers}\t{offers}\toffers_list\tread\t{body_uri}"),
            ],
        );
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let launched = home.launch_from(&dir, &agent).await.unwrap().0;
        assert_eq!(launched.status, "starting");
        let end = home.wait_ended(&launched.id).await;
        assert_eq!(end.cause.as_deref(), Some("completed"));
        grants.abort();

        let results = home.results(&agent);
        assert_eq!(results.len(), 2, "{results:?}");
        assert!(
            plan_outcome(&results, 0).starts_with("ok"),
            "{}",
            results[0]
        );
        assert!(
            plan_outcome(&results, 1).starts_with("ok"),
            "{}",
            results[1]
        );

        let requests = model.requests();
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert_eq!(
            requests[0],
            serde_json::json!({"path": body_uri, "op": "offers_list"}),
            "the invoke line still sends the path wrapper"
        );
        let mut expected = serde_json::from_slice::<serde_json::Value>(body.as_bytes())
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        expected.insert("op".to_string(), serde_json::json!("offers_list"));
        assert_eq!(
            requests[1],
            serde_json::Value::Object(expected),
            "the send line delivers the body file's own object, unwrapped"
        );
        assert_eq!(
            requests[1]["pad"],
            serde_json::json!("send body ✓ 𝄞"),
            "the body file's text arrives intact"
        );
    }

    /// Two agents work through one Runtime-issued model grant: each launch
    /// asks for the runs resource, creates one run, and records the answer
    /// under its own `UsersAI` root. The recorded answer is that agent's own
    /// task, and each stamped create names its own agent as the principal.
    #[cfg(unix)]
    #[tokio::test]
    async fn agent_task_through_bus_model_grant() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (dir, cid) = home.model_host("model-host", Some(1_140));
        let a = home.create_agent_for_host("model-a", &cid);
        let b = home.create_agent_for_host("model-b", &cid);
        let model = Arc::new(CapturingModelProvider::default());
        let registry = Arc::new(elastos_runtime::provider::ProviderRegistry::new());
        registry.register(model.clone()).await;
        registry.register(home.provider.clone()).await;
        home.runtime
            .set_provider_registry(
                registry,
                home.capability_manager.clone(),
                home.pending_store.clone(),
                home.data_dir.clone(),
            )
            .await;
        model.watch(home.runtime.clone());

        let tasks = [
            (a.as_str(), "request:agent-a", "count the sparks"),
            (b.as_str(), "request:agent-b", "name the ring"),
        ];
        assert_ne!(home.root(&a), home.root(&b), "each agent has its own root");
        for (agent, request_id, task) in tasks {
            let lines = [
                "invoke\telastos://model/offers\telastos://model/offers\toffers_list\tread\t"
                    .to_string(),
                task_create_line(&home, agent, request_id, task),
            ];
            run_model_lines(&home, &dir, agent, &lines).await;
            let results = home.results(agent);
            assert_eq!(results.len(), 2, "{results:?}");
            assert!(
                plan_outcome(&results, 0).starts_with("ok"),
                "the offers list reached the provider: {results:?}"
            );
            let outcome = plan_outcome(&results, 1);
            assert!(outcome.starts_with("ok "), "{results:?}");
            let (_, body) = outcome.split_once(' ').unwrap();
            let answer: serde_json::Value =
                serde_json::from_str(body).unwrap_or_else(|err| panic!("{err}: {outcome}"));
            assert_eq!(
                answer["data"]["terminal"]["output"]["text"],
                serde_json::json!(task),
                "the answer recorded under {agent}'s own root names its own task: {outcome}"
            );
        }
        // Agent B's turn left agent A's recorded answer where it was.
        for (agent, _, task) in tasks {
            let results = home.results(agent);
            let kept = plan_outcome(&results, 1);
            let (_, body) = kept.split_once(' ').unwrap();
            let kept: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                kept["data"]["terminal"]["output"]["text"],
                serde_json::json!(task),
                "{agent}'s own answer is still in its own root: {results:?}"
            );
        }
        let calls = create_calls(&model);
        assert_eq!(calls.len(), 2, "{calls:?}");
        assert_eq!(calls[0]["runtime_binding"]["principal_id"], a);
        assert_eq!(calls[1]["runtime_binding"]["principal_id"], b);
        assert_eq!(calls[0]["input"]["prompt"], "count the sparks");
        assert_eq!(calls[1]["input"]["prompt"], "name the ring");
    }

    /// A plan line whose grant names the probe's own journal while the invoke
    /// still reaches for the model runs resource: the Runtime refuses the
    /// capability mismatch and the provider records nothing.
    #[cfg(unix)]
    #[tokio::test]
    async fn agent_model_call_without_the_grant_is_refused() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let (home, dir, agent, model) = admitted_model_agent(Some(1_140)).await;
        let granted = task_create_line(&home, &agent, "request:no-grant", "count the sparks");
        let journal = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
        let mut fields: Vec<&str> = granted.split('\t').collect();
        fields[1] = journal;
        let outcome = run_model_lines(&home, &dir, &agent, &[fields.join("\t")]).await;
        assert!(
            outcome.contains("Capability validation failed"),
            "{outcome}"
        );
        assert!(
            create_calls(&model).is_empty(),
            "the refused create never reached the provider"
        );
        assert!(model.requests().is_empty(), "{:?}", model.requests());
    }

    #[cfg(unix)]
    /// A signed component that declares no agent has no ceiling entry, and
    /// its model invoke still reaches the provider. One call is recorded.
    #[tokio::test]
    async fn non_agent_reaches_model() {
        use elastos_compute::providers::ComponentProvider;
        use elastos_runtime::capability::{CapabilityManager, CapabilityStore};
        use elastos_runtime::primitives::metrics::MetricsManager;
        use elastos_runtime::provider::ProviderRegistry;
        use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
        use elastos_storage::providers::LocalFSProvider;

        let temp = tempfile::tempdir().unwrap();
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let key = SigningKey::from_bytes(&[0x45; 32]);
        runtime
            .configure_capsule_admission(
                &data_dir,
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store =
            Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit_log));
        let model = Arc::new(CapturingModelProvider::default());
        model.watch(runtime.clone());
        let registry = Arc::new(ProviderRegistry::new());
        registry.register(model.clone()).await;
        runtime
            .set_provider_registry(
                registry,
                capability_manager.clone(),
                pending_store.clone(),
                data_dir.clone(),
            )
            .await;

        let wasm = wat::parse_str(include_str!(
            "../../../../tests/fixtures/components/non-agent-model.wat"
        ))
        .expect("non-agent model guest");
        let dir = temp.path().join("capsule");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.component.wasm"), &wasm).unwrap();
        let mut manifest: elastos_common::CapsuleManifest = serde_json::from_str(&format!(
            r#"{{
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": "non-agent-model",
                "role": "app",
                "type": "wasm",
                "runtime_abi": "elastos.component/v1",
                "bus_contract": "{contract}",
                "wit_world_sha256": "{wit}",
                "execution": "component",
                "projections": ["cli"],
                "entrypoint": "app.component.wasm",
                "capabilities": ["elastos://model/*"]
            }}"#,
            contract = elastos_common::ELASTOS_BUS_V1_CONTRACT,
            wit = elastos_common::elastos_bus_v1_wit_sha256(),
        ))
        .unwrap();
        assert!(manifest.agent.is_none(), "this capsule declares no agent");
        assert_eq!(manifest.resources.model_token_ceiling(), 0);
        manifest.validate().unwrap();
        sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        crate::setup::record_install_cid(&data_dir, &dir, &dir);

        let grants = grant_probe_requests(pending_store, capability_manager);
        let launched = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            runtime.run_local(&dir, Vec::new()),
        )
        .await
        .expect("the non-agent launch finishes")
        .map_err(|err| format!("{err:#}"))
        .expect("the non-agent reaches the model");
        grants.abort();
        assert!(launched.manifest.agent.is_none());
        assert_eq!(model.requests().len(), 1, "{:?}", model.requests());
        assert_eq!(model.requests()[0]["op"], "offers_list");
        assert_eq!(
            model.ceilings_at_call(),
            vec![Vec::<(String, u64)>::new()],
            "a non-agent has no ceiling entry while the model call runs"
        );
    }

    async fn post_agent_grant(
        home: &ProbeLaunch,
        agent_id: &str,
        grant: &str,
    ) -> (StatusCode, String) {
        use axum::{body::Body, http::Request, routing::post};
        use tower::ServiceExt;
        let app = axum::Router::new()
            .route("/api/capsules", post(launch_capsule))
            .layer(Extension(Some(home.data_dir.clone())))
            .layer(Extension(home.audit_log.clone()))
            .layer(Extension(home.runtime.clone()));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/capsules")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "path": home.capsule_dir,
                            "agent_id": agent_id,
                            "launch_grant": grant,
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn agent_launch_selected_resource_and_short_lifetime_guard_the_router() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a", "b"]).await;
        let a = &home.agents[0];
        let b = &home.agents[1];
        let bound = |id: &str| {
            gateway::issue_home_agent_launch_token_with_context(
                &home.data_dir,
                id,
                PROBE_HOST,
                &home.context,
            )
            .unwrap()
        };
        let other_agent = bound(b);
        let host_only = gateway::issue_home_launch_token_with_context(
            &home.data_dir,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        let hop_grant = gateway::issue_home_projection_launch_token_with_context(
            &home.data_dir,
            PROBE_HOST,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        let now = crate::auth::now_ts();
        let overlong = gateway::issue_home_agent_launch_token_at_for_test(
            &home.data_dir,
            a,
            PROBE_HOST,
            &home.context,
            now,
            now + 61,
        )
        .unwrap();
        let expired = gateway::issue_home_agent_launch_token_at_for_test(
            &home.data_dir,
            a,
            PROBE_HOST,
            &home.context,
            now - 61,
            now - 1,
        )
        .unwrap();
        for (case, grant) in [
            ("other agent", other_agent),
            ("host only", host_only),
            ("12 hour hop", hop_grant),
            ("over 60 seconds", overlong),
            ("expired", expired),
        ] {
            let (status, body) = post_agent_grant(&home, a, &grant).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {body}");
            if case == "expired" {
                assert!(body.contains("expired"), "{case}: {body}");
            }
            assert!(
                home.runtime.list_capsules().await.is_empty(),
                "{case} started a guest"
            );
        }
        let good = bound(a);
        let (status, body) = post_agent_grant(&home, a, &good).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(answer["status"], "starting");
        assert_eq!(home.runtime.list_capsules().await.len(), 1);
        let event = home.audit_log.recent_events(1).pop().unwrap();
        let audit = serde_json::to_value(event).unwrap();
        assert_eq!(audit["type"], "capsule_launch");
        assert_eq!(audit["agent_id"], a.as_str());
        assert_eq!(audit["owner"], home.owner);
        assert_eq!(audit["session_id"], answer["session_id"]);
        assert!(audit["cid"].as_str().is_some_and(|cid| !cid.is_empty()));
        assert!(audit["launch_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("launch:")));
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let ended = home
            .wait_ended(answer["session_id"].as_str().unwrap())
            .await;
        assert_eq!(ended.cause.as_deref(), Some("completed"), "the guest ran");
        grants.abort();
    }

    /// The router row above refuses an already-expired token at the gateway
    /// (`home launch token expired`) and never calls `start_agent_once`. This
    /// row verifies a grant while that check still accepts it, then calls the
    /// Runtime gate once the same `expires_at` is in the past.
    #[tokio::test]
    async fn agent_launch_grant_past_expiry_is_refused_at_the_runtime_gate() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = &home.agents[0];
        let issued_at = crate::auth::now_ts();
        // Inside the 60-second agent cap, and long enough that verification
        // finishes while the grant is still valid. The gate then waits out
        // this same lifetime on the wall clock.
        let expires_at = issued_at + 2;
        let grant = gateway::issue_home_agent_launch_token_at_for_test(
            &home.data_dir,
            agent,
            PROBE_HOST,
            &home.context,
            issued_at,
            expires_at,
        )
        .unwrap();
        let (launcher, launch_id, verified_exp) =
            super::agent_launch_grant(&home.data_dir, PROBE_HOST, agent, Some(grant))
                .expect("the grant is valid when the gateway verifies it");
        assert_eq!(verified_exp, expires_at);
        assert!(
            verified_exp > crate::auth::now_ts(),
            "verification finished before the grant expired"
        );
        let principal = launcher.principal_str().to_string();
        let walked = crate::agent_admission::walk_launch(&home.capsule_dir).unwrap();
        let admission = super::admit_agent_launch(
            Some(&home.data_dir),
            walked,
            Some(principal.as_str()),
            agent,
        )
        .expect("the stored agent is admitted");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if verified_exp <= now {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the wall clock did not reach the verified expiry"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let err = home
            .runtime
            .start_agent_once(
                &home.capsule_dir,
                admission,
                crate::runtime::AgentStartFacts {
                    agent_id: agent,
                    owner: principal.as_str(),
                    host_cid: "cid",
                    launch_id: &launch_id,
                    expires_at: verified_exp,
                    data_dir: &home.data_dir,
                },
            )
            .await
            .expect_err("the runtime gate refuses the expired grant");
        match err {
            elastos_common::ElastosError::InvalidManifest(message) => {
                assert_eq!(message, "agent launch grant expired");
            }
            other => panic!("expected the runtime expiry refusal, got {other}"),
        }
        assert!(
            home.runtime.list_capsules().await.is_empty(),
            "an expired grant started a guest"
        );
    }

    #[tokio::test]
    async fn agent_launch_id_is_one_use_after_the_guest_ends() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = &home.agents[0];
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let (status, body) = post_agent_grant(&home, agent, &grant).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
        let ended = home
            .wait_ended(answer["session_id"].as_str().unwrap())
            .await;
        assert_eq!(
            ended.cause.as_deref(),
            Some("completed"),
            "the first guest ran"
        );
        grants.abort();
        let (status, body) = post_agent_grant(&home, agent, &grant).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "replayed launch_id: {body}"
        );
        assert!(body.contains("already used"), "{body}");
        assert_eq!(
            home.runtime.list_capsules().await.len(),
            1,
            "replay started no guest"
        );
    }

    #[tokio::test]
    async fn agent_launch_double_click_with_one_grant_starts_one_guest() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = &home.agents[0];
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        let (first, second) = tokio::join!(
            post_agent_grant(&home, agent, &grant),
            post_agent_grant(&home, agent, &grant)
        );
        let (success, refusal) = match (first, second) {
            ((StatusCode::OK, success), (StatusCode::CONFLICT, refusal))
            | ((StatusCode::CONFLICT, refusal), (StatusCode::OK, success)) => (success, refusal),
            other => panic!("double click outcomes: {other:?}"),
        };
        assert_eq!(refusal, "this agent is already running", "{refusal}");
        let answer: serde_json::Value = serde_json::from_str(&success).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if !home.pending_store.list_pending().await.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the first guest remains live in its bridge call");
        assert_eq!(
            home.runtime.list_capsules().await.len(),
            1,
            "double click started only one guest"
        );
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        home.wait_ended(answer["session_id"].as_str().unwrap())
            .await;
        grants.abort();
    }

    #[tokio::test]
    async fn agent_launch_end_records_the_real_reason_and_drops_the_session() {
        use elastos_runtime::primitives::audit::{AuditEvent, StopReason};
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = &home.agents[0];
        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        let (status, body) = post_agent_grant(&home, agent, &grant).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let answer: serde_json::Value = serde_json::from_str(&body).unwrap();
        let session = answer["session_id"].as_str().unwrap().to_string();
        home.wait_pending(&session).await;
        assert!(
            home.runtime.agent_session(&session).await.is_some(),
            "the running guest has no start record"
        );
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let ended = home.wait_ended(&session).await;
        grants.abort();
        assert_eq!(ended.cause.as_deref(), Some("completed"));
        // `ended_at` is published before the start record is removed, so the
        // wait can return in that gap. The record is gone once the end returns.
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if home.runtime.agent_session(&session).await.is_none() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("a guest that ended on its own kept its start record");
        let stops: Vec<_> = home
            .audit_log
            .recent_events(usize::MAX)
            .into_iter()
            .filter_map(|event| match event {
                AuditEvent::CapsuleStop {
                    capsule_id,
                    reason,
                    agent_id,
                    owner,
                    cid,
                    launch_id,
                    session_id,
                    ..
                } if capsule_id == session => {
                    Some((reason, agent_id, owner, cid, launch_id, session_id))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            stops.len(),
            1,
            "the guest's own end wrote one stop: {stops:?}"
        );
        assert!(
            matches!(stops[0].0, StopReason::Completed),
            "a guest that ended on its own was audited as requested: {stops:?}"
        );
        assert_eq!(stops[0].1.as_deref(), Some(agent.as_str()));
        assert_eq!(stops[0].2.as_deref(), Some(home.owner.as_str()));
        assert!(stops[0].3.as_ref().is_some_and(|cid| !cid.is_empty()));
        assert!(stops[0]
            .4
            .as_ref()
            .is_some_and(|id| id.starts_with("launch:")));
        assert_eq!(stops[0].5.as_deref(), Some(session.as_str()));
        let response = stop_agent_session(
            Extension(home.runtime.clone()),
            Extension(home.audit_log.clone()),
            axum::body::Bytes::from(serde_json::json!({ "agent_id": agent }).to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let again = home.audit_log.recent_events(usize::MAX).into_iter().filter(|event| {
            matches!(event, AuditEvent::CapsuleStop { capsule_id, .. } if capsule_id == &session)
        }).count();
        assert_eq!(
            again, 1,
            "a stop after the guest ended wrote another record"
        );
    }

    #[tokio::test]
    async fn agent_launch_stop_route_follows_the_build() {
        use axum::body::Body;
        use axum::http::Request;
        use elastos_runtime::capability::{
            CapabilityManager, CapabilityStore, PendingRequestStore,
        };
        use elastos_runtime::primitives::metrics::MetricsManager;
        use elastos_runtime::session::SessionRegistry;
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            elastos_storage::providers::LocalFSProvider::new(dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            None,
        ));
        let audit = Arc::new(AuditLog::new());
        let sessions = Arc::new(SessionRegistry::new(audit.clone()));
        let shell = sessions
            .create_session(elastos_runtime::session::SessionType::Shell, None)
            .await;
        let store = Arc::new(CapabilityStore::new());
        let manager = Arc::new(CapabilityManager::new(
            store.clone(),
            audit.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending = Arc::new(PendingRequestStore::new(audit));
        let app = crate::api::server::tests::test_server(
            runtime,
            sessions,
            manager,
            store,
            pending,
            Some(dir.path().to_path_buf()),
        );
        // A shell session gets past the router's auth. An empty body then
        // reaches the stop handler only when that route is mounted. An
        // unmatched path on this router is 404, or 405 where `/:id` is the
        // only capsules path.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/capsules/stop-agent")
                    .header("content-type", "application/json")
                    .header(
                        axum::http::header::AUTHORIZATION,
                        format!("Bearer {}", shell.token),
                    )
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        if crate::agents::build_allows() {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
            assert!(
                text.contains("invalid_stop_request"),
                "the agents build did not run the stop handler: {status} {text}"
            );
        } else {
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "a build without agents mounted stop-agent: {status} {text}"
            );
            assert!(
                !text.contains("invalid_stop_request"),
                "a build without agents ran the stop handler: {text}"
            );
        }
    }

    #[tokio::test]
    async fn agent_launch_feature_off_refuses_before_start() {
        use crate::runtime::tests::test_runtime;
        if crate::agents::require_build().is_ok() {
            return;
        }
        use axum::{body::Body, http::Request, routing::post};
        use tower::ServiceExt;
        let (runtime, temp) = test_runtime().await;
        let runtime = Arc::new(runtime);
        let app = axum::Router::new()
            .route("/api/capsules", post(launch_capsule))
            .layer(Extension(Some(temp.path().to_path_buf())))
            .layer(Extension(Arc::new(AuditLog::new())))
            .layer(Extension(runtime.clone()));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/capsules")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"path":"unused", "agent_id":"agent:v2:test"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(runtime.list_capsules().await.is_empty());
    }

    /// Storage-grant rows. Their body is compiled only in the agents build.
    /// The next module is the skip a build without them lists, with the reason.
    #[cfg(unix)]
    mod instance_storage_rows;
    #[cfg(unix)]
    mod instance_storage_rows_feature_off;

    /// A Stop whose wait ends while the row is still running must say stopping.
    /// Today the same row is listed under `stopped` with status `running`.
    #[tokio::test]
    async fn a_stop_that_does_not_end_says_stopping_not_stopped() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        runtime
            .plant_open_agent_stop_for_test(agent, "session-held")
            .await;
        let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_millis(20));
        let response = stop_agent_session(
            Extension(runtime.clone()),
            Extension(Arc::new(AuditLog::new())),
            axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
        )
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let ended = runtime
            .get_capsule("session-held")
            .await
            .and_then(|info| info.ended_at);
        let stopped_rows = body["stopped"].as_array().map(Vec::len).unwrap_or(0);
        let stopping_status = body["stopping"]
            .get(0)
            .and_then(|row| row["status"].as_str());
        assert!(
            status == StatusCode::ACCEPTED
                && stopped_rows == 0
                && stopping_status == Some("stopping")
                && body["stopping"][0]["session_id"] == "session-held"
                && ended.is_none(),
            "a session that is still running was answered as stopped: {status} {body} ended={ended:?}"
        );
    }

    /// Stop marks the agent before it reads the rows, so a Start in that
    /// window is refused instead of adding a session the Stop never sees.
    #[tokio::test]
    async fn stop_marks_the_agent_before_it_reads_rows() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        runtime
            .plant_open_agent_stop_for_test(agent, "session-held")
            .await;
        runtime.arm_stop_mark_probe(agent);
        let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_millis(20));
        let response = stop_agent_session(
            Extension(runtime.clone()),
            Extension(Arc::new(AuditLog::new())),
            axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            runtime.stop_mark_seen_before_rows(agent),
            Some(true),
            "Stop read its rows before the agent was marked stopping"
        );
        assert!(
            !runtime.agent_stop_flag_is_set(agent).await,
            "the stopping flag stayed set after Stop returned"
        );
    }

    async fn start_refused_because_stopping(runtime: &Arc<Runtime>, agent: &str) -> bool {
        let result = launch_capsule(
            Extension(runtime.clone()),
            Extension(Arc::new(AuditLog::new())),
            Extension(Some(std::path::PathBuf::from("unused-home"))),
            Json(LaunchRequest {
                path: "unused".to_string(),
                principal_id: None,
                launch_grant: None,
                agent_id: Some(agent.to_string()),
            }),
        )
        .await;
        match result {
            Err((StatusCode::CONFLICT, body)) => {
                body.contains(crate::runtime::Runtime::AGENT_STOPPING)
                    || body.contains("agent_stopping")
            }
            _ => false,
        }
    }

    /// A Stop dropped during its wait must not leave Start refused after the
    /// session ends. While the session still runs, Start stays refused.
    #[tokio::test]
    async fn a_dropped_stop_allows_start_after_the_session_ends() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        runtime
            .plant_open_agent_stop_for_test(agent, "session-held")
            .await;
        let _limit = runtime.limit_stop_wait_for_test(std::time::Duration::from_secs(5));
        let task = tokio::spawn({
            let runtime = runtime.clone();
            let agent = agent.to_string();
            async move {
                stop_agent_session(
                    Extension(runtime),
                    Extension(Arc::new(AuditLog::new())),
                    axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if runtime.requested_stop_for_test("session-held").is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Stop did not reach its wait");
        task.abort();
        let _ = task.await;
        assert!(
            start_refused_because_stopping(&runtime, agent).await,
            "Start was allowed while the session still runs"
        );
        runtime.end_planted_session_for_test("session-held").await;
        assert!(
            !start_refused_because_stopping(&runtime, agent).await,
            "a dropped Stop left Start refused after the session ended"
        );
        assert!(
            !runtime.agent_stop_flag_is_set(agent).await,
            "a dropped Stop left the stopping mark set"
        );
    }

    /// A planted row and its live-run token stay one fact. Ending one planted
    /// row removes only that row's token.
    #[tokio::test]
    async fn a_planted_row_keeps_its_live_run_in_step() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let other = "agent:v2:fedcba9876543210fedcba9876543210";
        assert!(!runtime.agent_live_run_held(agent));
        runtime
            .plant_open_agent_stop_for_test(agent, "session-held")
            .await;
        assert!(
            runtime.agent_live_run_held(agent),
            "planting a live row did not admit its run"
        );
        assert!(!runtime.agent_live_run_held(other));
        runtime
            .plant_open_agent_stop_for_test(agent, "session-other")
            .await;
        runtime.end_planted_session_for_test("session-held").await;
        assert!(
            runtime.agent_live_run_held(agent),
            "ending one planted row cleared the other row's run"
        );
        runtime.end_planted_session_for_test("session-other").await;
        assert!(
            !runtime.agent_live_run_held(agent),
            "ending the planted rows left the agent live"
        );
    }

    #[cfg(unix)]
    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<String>() {
            return message.clone();
        }
        if let Some(message) = payload.downcast_ref::<&str>() {
            return (*message).to_string();
        }
        "panic payload was not a string".to_string()
    }

    /// A write from a live agent session, through the bridge that session holds.
    /// `uri` may name `UsersAI/self`; the grant is the concrete root that alias
    /// becomes. A precondition is merged into the body, so `append` replaces
    /// the default.
    #[cfg(unix)]
    async fn write_in_session(
        home: &ProbeLaunch,
        session: &str,
        principal: &str,
        uri: &str,
        content: &[u8],
        precondition: serde_json::Value,
    ) -> serde_json::Value {
        use elastos_runtime::capability::{Action, ResourceId, TokenConstraints};
        let root = home.root(principal);
        let concrete = uri.replacen("localhost://UsersAI/self", &root, 1);
        let tables = home.runtime.bridge_tables_for_test(session);
        let token = home.capability_manager.grant(
            session,
            ResourceId::new(&concrete),
            Action::Write,
            TokenConstraints::default(),
            None,
        );
        let mut body = serde_json::json!({ "content": content.to_vec(), "append": false });
        if let Some(extra) = precondition.as_object() {
            for (key, value) in extra {
                body[key] = value.clone();
            }
        }
        let line = serde_json::json!({
            "id": 70,
            "request": {
                "type": "resource_invoke",
                "uri": uri,
                "operation": "write",
                "token": token.to_base64().expect("a minted token is base64"),
                "body": body,
            }
        })
        .to_string();
        let ctx = crate::resource_bridge::BridgeContext {
            provider_registry: home.registry.clone(),
            capability_manager: home.capability_manager.clone(),
            pending_store: home.pending_store.clone(),
            capsule_id: session.to_string(),
            session_id: session.to_string(),
            principal_id: Some(principal.to_string()),
            manifest_capabilities: tables.manifest_capabilities,
            data_dir: Some(home.data_dir.clone()),
            launch: tables.launch,
            model_token_ceiling: tables.model_token_ceiling,
            model_budget: None,
            stop: tables.stop,
            plan_book: None,
        };
        let answer = crate::resource_bridge::handle_component_resource_request(&line, ctx)
            .await
            .expect("the bridge answers a session write");
        home.capability_manager
            .revoke(*token.id(), "the session write")
            .await
            .expect("the session write grant is revoked");
        answer
    }

    #[cfg(unix)]
    fn write_ok_revision(answer: &serde_json::Value) -> String {
        assert_eq!(
            answer["response"]["result"]["status"], "ok",
            "the session write was refused: {answer}"
        );
        answer["response"]["result"]["data"]["revision"]
            .as_str()
            .unwrap_or_else(|| panic!("the write named no revision: {answer}"))
            .to_string()
    }

    #[cfg(unix)]
    fn object_bytes(home: &ProbeLaunch, principal: &str, suffix: &str) -> Vec<u8> {
        let root = home.root(principal);
        let uri = format!("{root}{suffix}");
        let path = elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &uri)
            .unwrap_or_else(|| panic!("{uri} is not a rooted path"));
        crate::auth::read_principal_root_object(&home.data_dir, principal, &root, &uri, &path)
            .unwrap_or_else(|err| panic!("{uri} is not readable: {err}"))
    }

    #[cfg(unix)]
    async fn live_of(home: &ProbeLaunch, agent: &str) -> usize {
        home.runtime
            .list_capsules()
            .await
            .into_iter()
            .filter(|info| info.ended_at.is_none() && info.principal.as_deref() == Some(agent))
            .count()
    }

    #[cfg(unix)]
    fn assert_stopping(result: Result<Json<LaunchResponse>, (StatusCode, String)>) {
        match result {
            Err((status, body)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(body, crate::runtime::Runtime::AGENT_STOPPING);
            }
            Ok(answer) => panic!(
                "a start during a landing effect was accepted: {}",
                answer.0.id
            ),
        }
    }

    #[cfg(unix)]
    fn assert_already_running(result: Result<Json<LaunchResponse>, (StatusCode, String)>) {
        match result {
            Err((status, body)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(body, crate::runtime::Runtime::AGENT_ALREADY_RUNNING);
            }
            Ok(answer) => panic!("a second start was accepted: {}", answer.0.id),
        }
    }

    #[cfg(unix)]
    async fn launch_grant(
        home: &ProbeLaunch,
        dir: &std::path::Path,
        agent: &str,
        grant: &str,
    ) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
        launch_capsule(
            Extension(home.runtime.clone()),
            Extension(home.audit_log.clone()),
            Extension(Some(home.data_dir.clone())),
            Json(LaunchRequest {
                path: dir.to_string_lossy().into_owned(),
                principal_id: None,
                launch_grant: Some(grant.to_string()),
                agent_id: Some(agent.to_string()),
            }),
        )
        .await
    }

    /// One agent, one live run. A second grant is refused with the stable
    /// sentence, and that grant is not consumed. The live run can still write.
    /// A different agent runs beside it. Stop frees the agent, and the refused
    /// grant can then start.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_second_start_is_refused_while_the_first_run_can_write() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["other"]).await;
        let other = home.agents[0].clone();
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        let journal = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
        let notes = "localhost://UsersAI/self/memory/notes.md";
        let journal_suffix = "/.AppData/Agents/agent-host/tasks/t1/journal";
        let notes_suffix = "/memory/notes.md";

        let beside = home.launch(&other).await.unwrap().0;
        home.wait_pending(&beside.id).await;
        let first = home.launch_from(&spin_dir, &agent).await.unwrap().0;
        home.wait_running(&first.id).await;
        assert_eq!(live_of(&home, &agent).await, 1);
        assert_eq!(live_of(&home, &other).await, 1);
        let revision = write_ok_revision(
            &write_in_session(
                &home,
                &first.id,
                &agent,
                journal,
                b"journal v1",
                serde_json::json!({ "create_only": true }),
            )
            .await,
        );
        assert_eq!(object_bytes(&home, &agent, journal_suffix), b"journal v1");

        let grant = gateway::issue_home_agent_launch_token_with_context(
            &home.data_dir,
            &agent,
            PROBE_HOST,
            &home.context,
        )
        .unwrap();
        assert_already_running(launch_grant(&home, &spin_dir, &agent, &grant).await);
        assert_eq!(live_of(&home, &agent).await, 1);
        let next = write_ok_revision(
            &write_in_session(
                &home,
                &first.id,
                &agent,
                journal,
                b"journal v2",
                serde_json::json!({ "if_revision": &revision }),
            )
            .await,
        );
        assert_ne!(next, revision);
        assert_eq!(object_bytes(&home, &agent, journal_suffix), b"journal v2");
        write_ok_revision(
            &write_in_session(
                &home,
                &first.id,
                &agent,
                notes,
                b"one",
                serde_json::json!({}),
            )
            .await,
        );
        write_ok_revision(
            &write_in_session(
                &home,
                &first.id,
                &agent,
                notes,
                b"two",
                serde_json::json!({ "append": true }),
            )
            .await,
        );
        assert_eq!(object_bytes(&home, &agent, notes_suffix), b"onetwo");
        assert_eq!(live_of(&home, &other).await, 1);
        assert_eq!(object_bytes(&home, &agent, journal_suffix), b"journal v2");

        let (status, _) = stop_route(&home, &first.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(live_of(&home, &agent).await, 0);
        let again = launch_grant(&home, &spin_dir, &agent, &grant)
            .await
            .expect("stop frees the agent, and the refused grant was not used");
        home.wait_running(&again.0.id).await;
        assert_eq!(live_of(&home, &agent).await, 1);
        assert_ne!(again.0.id, first.id);
        let (status, _) = stop_route(&home, &again.0.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let beside_end = home.wait_ended(&beside.id).await;
        grants.abort();
        assert_eq!(beside_end.cause.as_deref(), Some("completed"));
        assert_eq!(live_of(&home, &other).await, 0);
    }

    /// Notifies one waiter when dropped, so a pause is released on every path.
    #[cfg(unix)]
    struct ReleasePause(Arc<tokio::sync::Notify>);

    #[cfg(unix)]
    impl Drop for ReleasePause {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    /// The ending drops the token after the row records its end. A later Start
    /// waits until that drop is visible.
    #[cfg(unix)]
    async fn wait_token_clear(home: &ProbeLaunch, agent: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while home.runtime.agent_live_run_held(agent) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{agent} still holds a live run"));
    }

    /// A guest that fails, then a later Start of the same agent. The failure is
    /// the probe's peer read. The token is clear before the later Start.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_guest_failure_then_a_start_is_admitted() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["x", "y"]).await;
        let [x, y] = home.agents.as_slice() else {
            panic!("two agents");
        };
        let (root_x, root_y) = (home.root(x), home.root(y));
        let peer = format!("{root_y}/memory/notes.md");
        let pointer_uri = format!("{root_x}/memory/peer");
        let pointer_path =
            elastos_common::localhost::rooted_localhost_fs_path(&home.data_dir, &pointer_uri)
                .unwrap();
        crate::auth::write_principal_root_object(
            &home.data_dir,
            x,
            &root_x,
            &pointer_uri,
            &pointer_path,
            peer.as_bytes(),
        )
        .unwrap();
        let grants =
            grant_probe_requests(home.pending_store.clone(), home.capability_manager.clone());
        let first = home.launch(x).await.expect("the first start is admitted").0;
        let ended = home.wait_ended(&first.id).await;
        assert_eq!(ended.status, "failed", "{ended:?}");
        wait_token_clear(&home, x).await;
        let second = home
            .launch(x)
            .await
            .expect("a Start after the guest fails")
            .0;
        assert_eq!(second.status, "starting");
        assert_ne!(second.id, first.id);
        let _ = home.wait_ended(&second.id).await;
        grants.abort();
    }

    /// A guest that crashes, then a later Start of the same agent. The crash is
    /// `unreachable` in `run`. The token is clear before the later Start.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_guest_crash_then_a_start_is_admitted() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (dir, cid) = home.host_of("crash-host", CRASH_COMPONENT);
        let agent = home.create_agent_for_host("crashing", &cid);
        let first = home
            .launch_from(&dir, &agent)
            .await
            .expect("the crashing guest is admitted")
            .0;
        let ended = home.wait_ended(&first.id).await;
        assert_eq!(ended.status, "failed", "{ended:?}");
        let cause = ended.cause.unwrap_or_default();
        assert!(
            cause.contains("unreachable") || cause.contains("trap"),
            "{cause}"
        );
        wait_token_clear(&home, &agent).await;
        let second = home
            .launch_from(&dir, &agent)
            .await
            .expect("a Start after the guest crashes")
            .0;
        assert_eq!(second.status, "starting");
        assert_ne!(second.id, first.id);
        let _ = home.wait_ended(&second.id).await;
    }

    /// Two different agents start at the same moment. Each token stays with
    /// the launch that admitted it. The first launch is paused after it
    /// admitted its token and before it takes that token into the activation.
    /// The second launch runs through that window.
    #[cfg(unix)]
    #[tokio::test]
    async fn two_different_agents_starting_at_once_keep_their_tokens() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (dir_a, cid_a) = home.host_of("spin-a", SPIN_COMPONENT);
        let (dir_b, cid_b) = home.host_of("spin-b", SPIN_COMPONENT);
        let agent_a = home.create_agent_for_host("agent-a", &cid_a);
        let agent_b = home.create_agent_for_host("agent-b", &cid_b);
        let pause = home.runtime.arm_live_run_await("entrypoint");
        let entered = pause.entered.notified();
        let home_a = Arc::clone(&home);
        let agent_a_task = agent_a.clone();
        let started = tokio::spawn(async move { home_a.launch_from(&dir_a, &agent_a_task).await });
        tokio::time::timeout(std::time::Duration::from_secs(30), entered)
            .await
            .expect("the first launch reaches the entrypoint");
        assert!(
            home.runtime.agent_live_run_held(&agent_a),
            "the first start admitted its token"
        );
        // The pause is released when this value drops, including a timeout.
        let release_pause = ReleasePause(Arc::clone(&pause.release));
        let second = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            home.launch_from(&dir_b, &agent_b),
        )
        .await;
        let b = match second {
            Ok(started) => {
                started
                    .expect("the other agent starts while the first is still loading")
                    .0
            }
            Err(_elapsed) => panic!("the other agent did not start within 60s"),
        };
        assert!(
            home.runtime.agent_live_run_held(&agent_a),
            "the first token stays with its own launch"
        );
        assert!(home.runtime.agent_live_run_held(&agent_b));
        drop(release_pause);
        let a = tokio::time::timeout(std::time::Duration::from_secs(60), started)
            .await
            .expect("the paused launch finishes")
            .expect("the paused launch task joins")
            .expect("the paused launch is admitted")
            .0;
        assert_ne!(a.id, b.id);
        assert!(home.runtime.agent_live_run_held(&agent_a));
        assert!(home.runtime.agent_live_run_held(&agent_b));
        let (status, _) = stop_route(&home, &a.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = stop_route(&home, &b.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A plain write outside `.AppData/Agents` replaces an existing file.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_plain_write_replaces_an_existing_file_outside_agents() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (dir, cid) = home.spin_host();
        let agent = home.create_agent_for_host("notes", &cid);
        let run = home
            .launch_from(&dir, &agent)
            .await
            .expect("the notes guest starts")
            .0;
        home.wait_running(&run.id).await;
        let notes = "localhost://UsersAI/self/memory/notes.md";
        let _ = write_ok_revision(
            &write_in_session(&home, &run.id, &agent, notes, b"one", serde_json::json!({})).await,
        );
        let _ = write_ok_revision(
            &write_in_session(&home, &run.id, &agent, notes, b"two", serde_json::json!({})).await,
        );
        assert_eq!(object_bytes(&home, &agent, "/memory/notes.md"), b"two");
        let (status, _) = stop_route(&home, &run.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Two starts of one agent at the same moment: the launch lock admits one.
    #[cfg(unix)]
    #[tokio::test]
    async fn two_starts_at_once_produce_one_run() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        let (first, second) = tokio::join!(
            home.launch_from(&spin_dir, &agent),
            home.launch_from(&spin_dir, &agent),
        );
        let winner = match (first, second) {
            (Ok(answer), Err((status, body))) | (Err((status, body)), Ok(answer)) => {
                assert_eq!(status, StatusCode::CONFLICT);
                assert_eq!(body, crate::runtime::Runtime::AGENT_ALREADY_RUNNING);
                assert!(!body.contains("already used"));
                answer.0.id
            }
            (Ok(a), Ok(b)) => panic!("both starts were accepted: {} and {}", a.0.id, b.0.id),
            (Err(a), Err(b)) => panic!("both starts were refused: {a:?} {b:?}"),
        };
        home.wait_running(&winner).await;
        assert_eq!(live_of(&home, &agent).await, 1);
        let (status, _) = stop_route(&home, &winner, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A launch cancelled at each await after admission frees the agent, and
    /// the next Start is then admitted.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_launch_cancelled_at_each_await_frees_the_agent() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        for point in crate::runtime::Runtime::LIVE_RUN_AWAIT_POINTS {
            let pause = home.runtime.arm_live_run_await(point);
            let route_home = home.clone();
            let route_dir = spin_dir.clone();
            let route_agent = agent.clone();
            let route =
                tokio::spawn(async move { route_home.launch_from(&route_dir, &route_agent).await });
            if tokio::time::timeout(std::time::Duration::from_secs(15), pause.entered.notified())
                .await
                .is_err()
            {
                route.abort();
                match route.await {
                    Ok(Ok(answer)) => panic!("{point} finished as {}", answer.0.status),
                    Ok(Err((status, body))) => panic!("{point} finished as {status} {body}"),
                    Err(err) => panic!("{point} was not reached: {err}"),
                }
            }
            route.abort();
            let _ = route.await;
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if !home.runtime.agent_live_run_held(&agent)
                        && live_of(&home, &agent).await == 0
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{point} left the agent live"));
            let started = match home.launch_from(&spin_dir, &agent).await {
                Ok(answer) => answer.0,
                Err((status, body)) => panic!("{point} did not free the agent: {status} {body}"),
            };
            assert_eq!(started.status, "starting", "{point}");
            home.wait_running(&started.id).await;
            let (status, body) = stop_route(&home, &started.id, Some("user")).await;
            assert_eq!(status, StatusCode::OK, "{point} stop: {body}");
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if !home.runtime.agent_live_run_held(&agent) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{point} stop left the live run set"));
        }
    }

    /// A panic after the run is admitted drops that run, and the next Start
    /// is admitted.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_panic_after_admission_frees_the_agent() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        let _pause = home.runtime.arm_live_run_panic("entrypoint");
        let route_home = home.clone();
        let route_dir = spin_dir.clone();
        let route_agent = agent.clone();
        let joined =
            tokio::spawn(async move { route_home.launch_from(&route_dir, &route_agent).await })
                .await;
        let Err(joined) = joined else {
            panic!("the admitted start returned");
        };
        let message = panic_message(joined.into_panic());
        assert!(
            message.contains("entrypoint"),
            "the panic was not the admission hook: {message}"
        );
        assert!(
            !home.runtime.agent_live_run_held(&agent),
            "the panic left the live run set"
        );
        let started = home
            .launch_from(&spin_dir, &agent)
            .await
            .expect("a panic frees the agent")
            .0;
        assert_eq!(started.status, "starting");
        home.wait_running(&started.id).await;
        let (status, _) = stop_route(&home, &started.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A start that is refused after its run was admitted frees the agent.
    /// The next Start, with a new grant, is admitted.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_refused_start_after_admission_frees_the_agent() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        let _armed = home.runtime.arm_refuse_after_live_admit();
        let refused = home.launch_from(&spin_dir, &agent).await;
        assert!(refused.is_err(), "the start after admission was accepted");
        drop(_armed);
        assert!(
            !home.runtime.agent_live_run_held(&agent),
            "the refused start left the live run set"
        );
        let started = home
            .launch_from(&spin_dir, &agent)
            .await
            .expect("a refused start frees the agent")
            .0;
        assert_eq!(started.status, "starting");
        home.wait_running(&started.id).await;
        let (status, _) = stop_route(&home, &started.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The first run has ended. A second run has started. The ended run cannot
    /// write, and a stale revision of the live run is a conflict.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_ended_run_cannot_write_after_the_next_run_starts() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&[]).await;
        let (spin_dir, spin_cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &spin_cid);
        let journal = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
        let suffix = "/.AppData/Agents/agent-host/tasks/t1/journal";

        let first = home.launch_from(&spin_dir, &agent).await.unwrap().0;
        home.wait_running(&first.id).await;
        let revision = write_ok_revision(
            &write_in_session(
                &home,
                &first.id,
                &agent,
                journal,
                b"journal v1",
                serde_json::json!({ "create_only": true }),
            )
            .await,
        );
        let (status, _) = stop_route(&home, &first.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);

        let second = home.launch_from(&spin_dir, &agent).await.unwrap().0;
        home.wait_running(&second.id).await;
        let stale = write_in_session(
            &home,
            &first.id,
            &agent,
            journal,
            b"from the ended run",
            serde_json::json!({ "if_revision": &revision }),
        )
        .await;
        assert_eq!(
            stale["response"]["code"], "manifest_capability_denied",
            "the ended run wrote after the next run started: {stale}"
        );
        assert_eq!(object_bytes(&home, &agent, suffix), b"journal v1");

        let stored = write_ok_revision(
            &write_in_session(
                &home,
                &second.id,
                &agent,
                journal,
                b"journal v2",
                serde_json::json!({ "if_revision": &revision }),
            )
            .await,
        );
        assert_eq!(object_bytes(&home, &agent, suffix), b"journal v2");
        let conflict = write_in_session(
            &home,
            &second.id,
            &agent,
            journal,
            b"stale",
            serde_json::json!({ "if_revision": &revision }),
        )
        .await;
        assert_eq!(
            conflict["response"]["result"]["code"], "revision_conflict",
            "a stale revision replaced the journal: {conflict}"
        );
        assert_eq!(object_bytes(&home, &agent, suffix), b"journal v2");
        assert_ne!(stored, revision);
        let (status, _) = stop_route(&home, &second.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// The token is still held when the row records `ended_at`, and it is
    /// gone once that end has returned.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_token_stays_until_the_row_records_its_end() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (dir, cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &cid);
        let run = home
            .launch_from(&dir, &agent)
            .await
            .expect("the spinning guest starts")
            .0;
        home.wait_running(&run.id).await;
        let pause = home.runtime.arm_live_run_await("ended");
        let entered = pause.entered.notified();
        let home_stop = Arc::clone(&home);
        let session = run.id.clone();
        let stopping =
            tokio::spawn(async move { stop_route(&home_stop, &session, Some("user")).await });
        let release_pause = ReleasePause(Arc::clone(&pause.release));
        tokio::time::timeout(std::time::Duration::from_secs(30), entered)
            .await
            .expect("the end reaches the recorded row");
        let info = home
            .runtime
            .get_capsule(&run.id)
            .await
            .expect("the row is still listed");
        assert!(info.ended_at.is_some(), "the row has not recorded its end");
        assert!(
            home.runtime.agent_live_run_held(&agent),
            "the token was released before the row recorded its end"
        );
        drop(release_pause);
        let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(30), stopping)
            .await
            .expect("the stop finishes")
            .expect("the stop task joins");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            !home.runtime.agent_live_run_held(&agent),
            "the token stayed after the end"
        );
    }

    /// One live session and one planted session of the same agent, each with
    /// its own grant, write one journal at the same revision. One write is
    /// `ok`. The other is `revision_conflict`. The file is the winner's bytes.
    #[cfg(unix)]
    #[tokio::test]
    async fn two_sessions_writing_one_journal_at_one_revision_have_one_winner() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = Arc::new(ProbeLaunch::new(&[]).await);
        let (dir, cid) = home.spin_host();
        let agent = home.create_agent_for_host("spinning", &cid);
        let journal = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
        let suffix = "/.AppData/Agents/agent-host/tasks/t1/journal";
        let run = home
            .launch_from(&dir, &agent)
            .await
            .expect("the live session starts")
            .0;
        home.wait_running(&run.id).await;
        let revision = write_ok_revision(
            &write_in_session(
                &home,
                &run.id,
                &agent,
                journal,
                b"journal v1",
                serde_json::json!({ "create_only": true }),
            )
            .await,
        );
        let planted = format!("{}-planted", run.id);
        home.runtime
            .register_capsule(crate::runtime::RunningCapsuleInfo {
                id: planted.clone(),
                name: "planted".to_string(),
                status: "running".to_string(),
                capsule_type: elastos_common::CapsuleType::Wasm,
                handle: None,
                session_id: planted.clone(),
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
                launch_id: format!("launch:{planted}"),
                session_id: planted.clone(),
            })
            .await;
        home.runtime
            .share_agent_model_account_for_test(&run.id, &planted);
        let live_bytes = b"from the live session";
        let planted_bytes = b"from the planted session";
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let live_home = Arc::clone(&home);
        let live_session = run.id.clone();
        let live_agent = agent.clone();
        let live_journal = journal.to_string();
        let live_revision = revision.clone();
        let live_barrier = Arc::clone(&barrier);
        let planted_home = Arc::clone(&home);
        let planted_session = planted.clone();
        let planted_agent = agent.clone();
        let planted_journal = journal.to_string();
        let planted_revision = revision.clone();
        let planted_barrier = barrier;
        let live_write = tokio::spawn(async move {
            live_barrier.wait().await;
            write_in_session(
                &live_home,
                &live_session,
                &live_agent,
                &live_journal,
                live_bytes,
                serde_json::json!({ "if_revision": live_revision }),
            )
            .await
        });
        let planted_write = tokio::spawn(async move {
            planted_barrier.wait().await;
            write_in_session(
                &planted_home,
                &planted_session,
                &planted_agent,
                &planted_journal,
                planted_bytes,
                serde_json::json!({ "if_revision": planted_revision }),
            )
            .await
        });
        let (live_answer, planted_answer) = tokio::join!(live_write, planted_write);
        let live_answer = live_answer.expect("the live write task joins");
        let planted_answer = planted_answer.expect("the planted write task joins");
        let outcome = |answer: &serde_json::Value| {
            let result = &answer["response"]["result"];
            (
                result["status"] == "ok",
                result["code"] == "revision_conflict",
            )
        };
        let (live_ok, live_conflict) = outcome(&live_answer);
        let (planted_ok, planted_conflict) = outcome(&planted_answer);
        assert!(
            (live_ok && planted_conflict) || (planted_ok && live_conflict),
            "one ok and one revision_conflict: live={live_answer} planted={planted_answer}"
        );
        let winner: &[u8] = if live_ok { live_bytes } else { planted_bytes };
        assert_eq!(object_bytes(&home, &agent, suffix), winner);
        let (status, _) = stop_route(&home, &run.id, Some("user")).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// Stop has set its mark and has not read the registry. There is no live
    /// row. Start in that window is refused. After this Stop exits, Start is
    /// allowed again.
    #[tokio::test]
    async fn start_is_refused_while_stop_is_marked_before_rows() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let pause = runtime.arm_stop_before_rows(agent);
        let task = tokio::spawn({
            let runtime = runtime.clone();
            let agent = agent.to_string();
            async move {
                stop_agent_session(
                    Extension(runtime),
                    Extension(Arc::new(AuditLog::new())),
                    axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), pause.entered.notified())
            .await
            .expect("Stop did not pause after its mark");
        assert!(
            runtime.list_capsules().await.is_empty(),
            "a live row was present before Stop read the registry"
        );
        assert!(
            start_refused_because_stopping(&runtime, agent).await,
            "Start was allowed after the mark and before the rows were read"
        );
        pause.release.notify_one();
        let response = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("Stop did not finish")
            .expect("Stop panicked");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(
            !runtime.agent_stop_flag_is_set(agent).await,
            "the mark stayed after Stop returned"
        );
        assert!(
            !start_refused_because_stopping(&runtime, agent).await,
            "a finished Stop left Start refused"
        );
    }

    /// Two Stops at once. The first to exit clears only its own token. The
    /// mark stays until the second exits.
    #[tokio::test]
    async fn two_stops_keep_the_mark_until_both_exit() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let pause = runtime.arm_stop_before_rows(agent);
        let first = tokio::spawn({
            let runtime = runtime.clone();
            let agent = agent.to_string();
            async move {
                stop_agent_session(
                    Extension(runtime),
                    Extension(Arc::new(AuditLog::new())),
                    axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
                )
                .await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), pause.entered.notified())
            .await
            .expect("the first Stop did not pause after its mark");
        let second = stop_agent_session(
            Extension(runtime.clone()),
            Extension(Arc::new(AuditLog::new())),
            axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
        )
        .await;
        assert_eq!(second.status(), StatusCode::NOT_FOUND);
        assert!(
            runtime.agent_stop_flag_is_set(agent).await,
            "the second Stop cleared the first Stop's mark"
        );
        assert!(
            start_refused_because_stopping(&runtime, agent).await,
            "Start was allowed while the first Stop still holds its mark"
        );
        pause.release.notify_one();
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), first)
            .await
            .expect("the first Stop did not finish")
            .expect("the first Stop panicked");
        assert_eq!(first.status(), StatusCode::NOT_FOUND);
        assert!(
            !runtime.agent_stop_flag_is_set(agent).await,
            "the mark stayed after both Stops exited"
        );
        assert!(
            !start_refused_because_stopping(&runtime, agent).await,
            "Start stayed refused after both Stops exited"
        );
    }

    /// A panic after the mark drops this Stop's token. Start is allowed again.
    #[tokio::test]
    async fn a_panic_in_stop_clears_its_mark() {
        let (runtime, _dir) = crate::runtime::tests::test_runtime().await;
        let runtime = Arc::new(runtime);
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        runtime.arm_stop_panic_after_mark(agent);
        let task = tokio::spawn({
            let runtime = runtime.clone();
            let agent = agent.to_string();
            async move {
                stop_agent_session(
                    Extension(runtime),
                    Extension(Arc::new(AuditLog::new())),
                    axum::body::Bytes::from(format!(r#"{{"agent_id":"{agent}"}}"#)),
                )
                .await
            }
        });
        let joined = task.await;
        assert!(joined.is_err(), "Stop did not panic");
        assert!(
            !runtime.agent_stop_flag_is_set(agent).await,
            "a panic in Stop left the stopping mark set"
        );
        assert!(
            !start_refused_because_stopping(&runtime, agent).await,
            "a panic in Stop left Start refused"
        );
    }

    mod instance_storage_rows;
    mod instance_storage_rows_feature_off;
}

/// `POST /api/launch/open` (shell only), `{cid}`: start the content at `cid`
/// for the person whose Home launch grant the shell carries, and keep its launch
/// for the page it pins (`page_launch.rs`). Answers the launch's id and the
/// page's name; a refusal names its reason.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenLaunchRequest {
    cid: String,
}

#[derive(Serialize)]
pub struct OpenLaunchResponse {
    id: String,
    page: String,
    entrypoint: String,
    content_name: String,
    binding: String,
}

pub async fn open_launch(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    headers: HeaderMap,
    Json(req): Json<OpenLaunchRequest>,
) -> Result<Json<OpenLaunchResponse>, (StatusCode, String)> {
    use crate::page_launch::OpenRefusal;
    let data_dir = data_dir.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "no data folder for launches".to_string(),
    ))?;
    let person = super::gateway::require_internal_shell_content_open_context(&data_dir, &headers)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    match runtime
        .open_for_page(&data_dir, &req.cid, person.principal_id())
        .await
    {
        Ok(opened) => Ok(Json(OpenLaunchResponse {
            id: opened.id,
            page: opened.page,
            entrypoint: opened.entrypoint,
            content_name: opened.content_name,
            binding: opened.binding,
        })),
        Err(OpenRefusal::Start(refusal)) => Err((
            StatusCode::BAD_REQUEST,
            format!("{}: {refusal}", refusal.code()),
        )),
        Err(OpenRefusal::NotContent) => Err((StatusCode::BAD_REQUEST, "not_content".into())),
        Err(OpenRefusal::PageEntrypointNotPlain) => {
            Err((StatusCode::BAD_REQUEST, "page_entrypoint_not_plain".into()))
        }
        Err(OpenRefusal::TooManyOpen) => Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_open_launches".into(),
        )),
        Err(OpenRefusal::NoPrincipal) => Err((StatusCode::UNAUTHORIZED, "no_principal".into())),
        Err(OpenRefusal::TooManyInFlight) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "too_many_opens_in_flight".into(),
        )),
        Err(OpenRefusal::OpenFailed) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "kept_launch_open_failed".into(),
        )),
        Err(OpenRefusal::PlaceLost) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "kept_launch_place_lost".into(),
        )),
        Err(OpenRefusal::TooManyInAll) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "too_many_kept_launches".into(),
        )),
    }
}

/// Who reads a kept launch: the page's own launch token, bound to
/// `elastos://launch/<id>/<content>/<binding>` with the page the launch was kept for as its
/// executable, gives the person. Nothing else does.
fn kept_launch_reader(
    runtime: &Runtime,
    data_dir: Option<&std::path::Path>,
    headers: &HeaderMap,
    id: &str,
) -> Result<Option<(String, String)>, &'static str> {
    let Some(page) = runtime.kept_launch_page(id) else {
        return Ok(None);
    };
    let Some(content_name) = runtime.kept_launch_content_name(id) else {
        return Ok(None);
    };
    let Some(binding) = runtime.kept_launch_binding(id) else {
        return Ok(None);
    };
    let bound = format!("elastos://launch/{id}/{content_name}/{binding}");
    let token = super::gateway::require_internal_shell_projection_context(
        data_dir.ok_or("not_found")?,
        headers,
        &bound,
        &page,
    )
    .map_err(|err| {
        if err.to_string().contains("kept_launch_grant_mismatch") {
            "kept_launch_grant_mismatch"
        } else {
            "not_found"
        }
    })?;
    Ok(Some((token.principal_id().to_string(), page)))
}

/// The answer to a read of a kept launch: its bytes, never stored by the
/// reader, or `not_found` for anything else alike.
fn kept_launch_answer(bytes: Option<Vec<u8>>) -> axum::response::Response {
    match bytes {
        Some(bytes) => (
            StatusCode::OK,
            [
                ("content-type", "application/octet-stream"),
                ("cache-control", "no-store"),
            ],
            bytes,
        )
            .into_response(),
        None => (StatusCode::NOT_FOUND, "not_found").into_response(),
    }
}

/// `GET /api/launch/:id/output/:name` (shell only, with the page's token):
/// what the program of a kept launch wrote under that one name.
pub async fn kept_launch_output(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    axum::extract::Path((id, name)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    let reader = match kept_launch_reader(&runtime, data_dir.as_deref(), &headers, &id) {
        Ok(reader) => reader,
        Err("kept_launch_grant_mismatch") => {
            return (StatusCode::FORBIDDEN, "kept_launch_grant_mismatch").into_response()
        }
        Err(_) => None,
    };
    let read = reader.and_then(|(person, page)| {
        let what = crate::page_launch::KeptRead::Output(&name);
        runtime.read_kept_launch(&id, &person, &page, what)
    });
    kept_launch_answer(read)
}

/// `GET /api/launch/:id/content/*path` (shell only, with the page's token):
/// the content's file at exactly that path, under the path rule of
/// `page_launch.rs`.
pub async fn kept_launch_content(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    axum::extract::Path((id, path)): axum::extract::Path<(String, String)>,
    headers: HeaderMap,
) -> axum::response::Response {
    let reader = match kept_launch_reader(&runtime, data_dir.as_deref(), &headers, &id) {
        Ok(reader) => reader,
        Err("kept_launch_grant_mismatch") => {
            return (StatusCode::FORBIDDEN, "kept_launch_grant_mismatch").into_response()
        }
        Err(_) => None,
    };
    let read = reader.and_then(|(person, page)| {
        let what = crate::page_launch::KeptRead::Content(&path);
        runtime.read_kept_launch(&id, &person, &page, what)
    });
    kept_launch_answer(read)
}

/// `GET /api/launch/:id/page/*path` (shell only): one file of the page a kept
/// launch was opened for, at exactly that plain path. No page token: the
/// page's files are not secret; the launch's id says which page.
pub async fn kept_launch_page_file(
    Extension(runtime): Extension<Arc<Runtime>>,
    axum::extract::Path((id, path)): axum::extract::Path<(String, String)>,
) -> axum::response::Response {
    kept_launch_answer(runtime.read_kept_page_file(&id, &path))
}

/// Tokens for the kept-launch tests, minted as the gateway mints them.
#[cfg(test)]
pub(crate) mod kept_launch_test_tokens {
    /// The person's own Home token.
    #[cfg(unix)]
    pub(crate) fn home(data_dir: &std::path::Path) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        super::super::gateway::issue_home_launch_token_with_context(data_dir, "home", &context)
            .unwrap()
    }

    pub(crate) fn shell(data_dir: &std::path::Path) -> String {
        let context =
            super::super::gateway::bind_device_session_grant(data_dir, &["home"]).unwrap();
        super::super::gateway::issue_home_projection_launch_token_with_context(
            data_dir,
            "home",
            "home-shell",
            &context,
        )
        .unwrap()
    }

    /// A page's token bound to `resource`, with `page` as its executable.
    #[cfg(unix)]
    pub(crate) fn page(data_dir: &std::path::Path, resource: &str, page: &str) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        super::super::gateway::issue_home_projection_launch_token_with_context(
            data_dir, resource, page, &context,
        )
        .unwrap()
    }

    /// The person these tokens are for.
    #[cfg(unix)]
    pub(crate) fn person(data_dir: &std::path::Path) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        context.principal_id().to_string()
    }
}
