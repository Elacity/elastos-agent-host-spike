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
use crate::agents::{Caller, CreateRequest, Refused};

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

/// A named refusal answers 409 with its reason. Anything else answers as the
/// System routes do, so a caller who fails the owner check gets 403.
fn agents_response<T: Serialize>(result: anyhow::Result<T>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => match error.downcast_ref::<Refused>() {
            Some(refused) => (StatusCode::CONFLICT, refused.to_string()).into_response(),
            None => system_error_response(error),
        },
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
    agents_response(agents_set_enabled(&state, &headers, true))
}

pub(super) async fn agents_disable(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    agents_response(agents_set_enabled(&state, &headers, false))
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
    agents_response(
        agents_owner(&state, &headers)
            .and_then(|owner| crate::agents::list(&state.data_dir, &owner.caller()))
            .map(|agents| serde_json::json!({ "agents": agents })),
    )
}

pub(super) async fn agents_retire(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    agents_response(agents_owner(&state, &headers).and_then(|owner| {
        let request: RetireRequest = agents_request(&body)?;
        // The record write that performs the retire also appends its signed
        // row (agents.rs `write`), so the retire and its record are one
        // operation and the audit chain trims its tail, so recording never
        // waits on a full audit file. A second `agent.retired` row here
        // would claim "ok" before the retire happened or error after the
        // record already changed, so this route adds none.
        crate::agents::retire(
            &state.data_dir,
            &owner.caller(),
            &request.agent_id,
            now_ts(),
        )
    }))
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
    agents_response(agents_owner(&state, &headers).and_then(|owner| {
        let request: ActiveRequest = agents_request(&body)?;
        crate::agents::set_active(
            &state.data_dir,
            &owner.caller(),
            &request.agent_id,
            request.active,
            now_ts(),
        )
    }))
}

/// The passkey step-up operation for one Start. The ceremony and the route
/// both name it, so a token minted for another action cannot start an agent.
const AGENT_START_OPERATION: &str = "agent.start";
/// How recently the passkey step must have finished. The token itself can
/// live 180 seconds, and wallet and other callers still allow that. Begin
/// and complete run immediately before Start, and this route has no caller
/// that needs the extra minute, so a Start older than two minutes is refused.
const AGENT_START_STEP_UP_MAX_AGE_SECS: u64 = 120;

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
    let step_up = consume_passkey_step_up_for_effect(
        &state.data_dir,
        request.step_up_token.trim(),
        &launch,
        AGENT_START_STEP_UP_MAX_AGE_SECS,
        AGENT_START_OPERATION,
        &serde_json::json!({ "agent_id": request.agent_id }),
        (false, |_| Ok(())),
    )?;
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
        Refused(format!(
            "agent '{}' was not started: its signed start request was not recorded: {error}",
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
        // The launch succeeded, so the host is running with no signed
        // completion row. The same stop path the Stop route uses ends the
        // session and signs each stop, and the Start refuses by name
        // instead of answering success for a start it could not record.
        let outcome = stop_runtime_agent(&state.data_dir, &request.agent_id).await?;
        for session in &outcome.stopped {
            append_agent_lifecycle_audit(
                &state.data_dir,
                "agent.stopped",
                &owner,
                AgentAuditIds {
                    challenge_id: None,
                    capsule_id: Some(host.package().name.as_str()),
                    session_id: Some(&session.session_id),
                },
                "ok",
                serde_json::json!({ "agent_id": request.agent_id, "cause": "unrecorded_start" }),
            )?;
        }
        return Err(Refused(format!(
            "agent '{}' was started but its signed completion row was not recorded, so it was stopped: {audit_error}",
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
struct AgentStopResponse {
    agent_id: String,
    stopped: Vec<AgentStoppedSession>,
}

pub(super) async fn agents_stop(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    agents_response(stop_agent(&state, &headers, &body).await)
}

/// The owner gate. With no agent id this is the admin check, and it runs
/// before the body is read. With an agent id it is that check plus "this
/// owner owns this agent". The agent may be off or retired, and the Home may
/// have turned agents off. A guest fails the admin check. Another owner fails
/// the ownership check. Either refusal happens before the Runtime is asked
/// to stop anything. The checked owner comes back, so the stop it authorized
/// can be signed in its name.
fn owner_may_stop(
    state: &GatewayState,
    headers: &HeaderMap,
    agent_id: Option<&str>,
) -> anyhow::Result<AgentsOwner> {
    let owner = agents_owner(state, headers)?;
    if let Some(agent_id) = agent_id {
        crate::agents::stored_agent_for_stop(
            &state.data_dir,
            &owner.principal.principal_id,
            agent_id,
        )?;
    }
    Ok(owner)
}

/// Owner check, then ask the Runtime to stop the live row whose principal is
/// this agent. The request carries the agent id and no capsule name. Every
/// session the Runtime ended is signed into the audit chain in the owner's
/// name, with the cause the Runtime recorded: the owner asked.
async fn stop_agent(
    state: &GatewayState,
    headers: &HeaderMap,
    body: &Bytes,
) -> anyhow::Result<AgentStopResponse> {
    owner_may_stop(state, headers, None)?;
    let request: AgentStopRequest = agents_request(body)?;
    let owner = owner_may_stop(state, headers, Some(&request.agent_id))?;
    let outcome = stop_runtime_agent(&state.data_dir, &request.agent_id).await?;
    if outcome.stopped.is_empty() {
        let message = match outcome.already.as_deref() {
            Some("stopping") => "this agent is already stopping",
            Some("stopped") => "this agent is already stopped",
            _ => "this agent has no running session",
        };
        return Err(Refused(message.to_string()).into());
    }
    let host = crate::agents::stored_agent_for_stop(
        &state.data_dir,
        &owner.principal.principal_id,
        &request.agent_id,
    )?;
    let capsule_id = host
        .record
        .agent_host_package
        .as_ref()
        .map(|package| package.name.as_str());
    for session in &outcome.stopped {
        append_agent_lifecycle_audit(
            &state.data_dir,
            "agent.stopped",
            &owner,
            AgentAuditIds {
                challenge_id: None,
                capsule_id,
                session_id: Some(&session.session_id),
            },
            "ok",
            serde_json::json!({ "agent_id": request.agent_id, "cause": "owner" }),
        )?;
    }
    Ok(AgentStopResponse {
        agent_id: request.agent_id,
        stopped: outcome
            .stopped
            .into_iter()
            .map(|session| AgentStoppedSession {
                session_id: session.session_id,
                status: session.status,
            })
            .collect(),
    })
}
