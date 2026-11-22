//! The owner's agent routes: turn agents on or off for this Home, create,
//! list, rename, retire, turn one agent on or off, and start one agent.
//! Start is the only route here that runs an agent. It asks the Home Runtime
//! to start the host; this route does not admit the guest itself.
//!
//! Every route makes the same owner check as the System guest-registration
//! route: a Home launch token for System, on a proof binding that is stored,
//! not revoked and an admin's. Before that check each route refuses by name
//! in a build without agents, and on a Runtime that is not the Home.

use super::*;
use crate::agents::{Caller, CreateRequest, Refused};

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
/// The step-up token's own lifetime. A caller cannot ask for a longer one.
const AGENT_START_STEP_UP_MAX_AGE_SECS: u64 = 180;

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
    consume_passkey_step_up_token(
        &state.data_dir,
        request.step_up_token.trim(),
        &launch,
        AGENT_START_STEP_UP_MAX_AGE_SECS,
        AGENT_START_OPERATION,
        &serde_json::json!({ "agent_id": request.agent_id }),
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
    let grant = issue_home_agent_launch_token_with_context(
        &state.data_dir,
        &request.agent_id,
        host.package().name.as_str(),
        &owner.context,
    )?;
    let started =
        launch_runtime_agent(&state.data_dir, host.directory(), &request.agent_id, &grant).await?;
    Ok(AgentLaunchResponse {
        agent_id: request.agent_id,
        capsule_id: started.capsule_id,
        session_id: started.session_id,
        status: started.status,
    })
}
