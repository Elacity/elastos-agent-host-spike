//! The owner's agent routes: turn agents on or off for this Home, create,
//! list and retire. No route here runs an agent.
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
