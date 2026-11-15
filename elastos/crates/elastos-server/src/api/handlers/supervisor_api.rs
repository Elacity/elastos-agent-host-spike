//! Supervisor HTTP endpoints — shell-only operations for capsule VM lifecycle.
//!
//! These endpoints expose the supervisor's control plane over HTTP so the shell
//! capsule (running inside a VM) can orchestrate capsule lifecycle:
//! ensure externals, ensure capsules, launch, stop.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, http::HeaderValue, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use crate::setup::detect_platform;
use crate::supervisor::{Supervisor, SupervisorRequest, SupervisorResponse};

#[derive(Clone)]
pub struct SupervisorState {
    pub supervisor: Arc<Supervisor>,
    pub data_dir: Option<PathBuf>,
}

// ── Request/Response types ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct EnsureExternalInput {
    pub name: String,
    /// Platform key matching components.json (e.g. "linux-amd64", "linux-arm64").
    /// Defaults to the host platform via setup::detect_platform().
    #[serde(default = "default_platform")]
    pub platform: String,
}

fn default_platform() -> String {
    detect_platform()
}

#[derive(Debug, Deserialize)]
pub struct EnsureCapsuleInput {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchCapsuleInput {
    pub name: String,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default)]
    pub principal_id: Option<serde_json::Value>,
    #[serde(default)]
    pub launch_grant: Option<String>,
    #[serde(default)]
    pub home_token: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct StopCapsuleInput {
    pub handle: String,
}

#[derive(Debug, Deserialize)]
pub struct WaitCapsuleInput {
    pub handle: String,
}

#[derive(Debug, Deserialize)]
pub struct ResolvePlanInput {
    pub target: String,
}

#[derive(Debug, Deserialize)]
pub struct StartGatewayInput {
    pub addr: String,
    #[serde(default)]
    pub cache_dir: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SupervisorOutput {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock_cid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolvePlanOutput {
    pub status: String,
    pub capsules: Vec<String>,
    pub externals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<SupervisorResponse> for SupervisorOutput {
    fn from(r: SupervisorResponse) -> Self {
        Self {
            status: r.status,
            path: r.path,
            handle: r.handle,
            vsock_cid: r.vsock_cid,
            error: r.error,
        }
    }
}

/// POST /api/supervisor/resolve-plan — resolve transitive capsule/external dependencies.
pub async fn resolve_plan(
    State(state): State<SupervisorState>,
    Json(input): Json<ResolvePlanInput>,
) -> Result<Json<ResolvePlanOutput>, (StatusCode, String)> {
    match state.supervisor.resolve_launch_plan(&input.target).await {
        Ok((capsules, externals)) => Ok(Json(ResolvePlanOutput {
            status: "ok".into(),
            capsules,
            externals,
            error: None,
        })),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// POST /api/supervisor/ensure-external — download/verify an external tool.
pub async fn ensure_external(
    State(state): State<SupervisorState>,
    Json(input): Json<EnsureExternalInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let req = SupervisorRequest::DownloadExternal {
        name: input.name,
        platform: input.platform,
    };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

/// POST /api/supervisor/ensure-capsule — download/verify a capsule artifact.
pub async fn ensure_capsule(
    State(state): State<SupervisorState>,
    Json(input): Json<EnsureCapsuleInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let req = SupervisorRequest::EnsureCapsule { name: input.name };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

/// POST /api/supervisor/launch-capsule — boot a capsule in a crosvm VM.
pub async fn launch_capsule(
    State(state): State<SupervisorState>,
    Json(input): Json<LaunchCapsuleInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let principal_id = supervisor_launch_principal_from_input(state.data_dir.as_deref(), &input)?;
    let req = SupervisorRequest::LaunchCapsule {
        name: input.name,
        config: input.config,
        principal_id,
    };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

const SUPERVISOR_PRINCIPAL_AUTHORITY_KEYS: &[&str] =
    &["principal_id", "launch_grant", "home_token"];

fn supervisor_launch_principal_from_input(
    data_dir: Option<&Path>,
    input: &LaunchCapsuleInput,
) -> Result<Option<crate::resource_bridge::BridgePrincipal>, (StatusCode, String)> {
    let has_top_level_authority = [
        input.principal_id.as_ref().map(|_| "principal_id"),
        input.home_token.as_ref().map(|_| "home_token"),
    ]
    .into_iter()
    .flatten()
    .next();
    if let Some(key) = has_top_level_authority {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "supervisor launches do not accept raw principal authority ({key}); use signed launch_grant"
            ),
        ));
    }

    if let Some(config) = input.config.as_object() {
        for key in SUPERVISOR_PRINCIPAL_AUTHORITY_KEYS {
            if config.contains_key(*key) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "supervisor launch config must not carry {key}; use the signed Home launch-grant path"
                    ),
                ));
            }
        }
    }

    let Some(grant) = input
        .launch_grant
        .as_deref()
        .map(str::trim)
        .filter(|grant| !grant.is_empty())
    else {
        return Ok(None);
    };

    let data_dir = data_dir.ok_or((
        StatusCode::BAD_REQUEST,
        "principal launch grant unavailable".to_string(),
    ))?;
    let mut headers = HeaderMap::new();
    let header_value = HeaderValue::from_str(grant).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "invalid launch_grant header value".to_string(),
        )
    })?;
    headers.insert("x-elastos-home-token", header_value);
    let principal = crate::api::gateway::require_internal_shell_launch_grant_principal(
        data_dir,
        &headers,
        &[input.name.as_str()],
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    Ok(Some(principal))
}

/// POST /api/supervisor/stop-capsule — stop a running capsule VM.
pub async fn stop_capsule(
    State(state): State<SupervisorState>,
    Json(input): Json<StopCapsuleInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let req = SupervisorRequest::StopCapsule {
        handle: input.handle,
    };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

/// POST /api/supervisor/wait-capsule — wait for a running capsule VM to exit.
pub async fn wait_capsule(
    State(state): State<SupervisorState>,
    Json(input): Json<WaitCapsuleInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let req = SupervisorRequest::WaitCapsule {
        handle: input.handle,
    };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

/// POST /api/supervisor/start-gateway — start/reuse runtime gateway server.
pub async fn start_gateway(
    State(state): State<SupervisorState>,
    Json(input): Json<StartGatewayInput>,
) -> Result<Json<SupervisorOutput>, (StatusCode, String)> {
    let req = SupervisorRequest::StartGateway {
        addr: input.addr,
        cache_dir: input.cache_dir,
    };
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch_input(value: serde_json::Value) -> LaunchCapsuleInput {
        serde_json::from_value(value).expect("launch input should parse")
    }

    #[test]
    fn supervisor_launch_rejects_top_level_principal_authority() {
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "principal_id": "person:local:admin"
        }));

        let err = supervisor_launch_principal_from_input(None, &input)
            .expect_err("principal_id must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
            .contains("supervisor launches do not accept raw principal authority"));
    }

    #[test]
    fn supervisor_launch_rejects_config_principal_authority() {
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "config": {
                "launch_grant": "signed-home-grant"
            }
        }));

        let err = supervisor_launch_principal_from_input(None, &input)
            .expect_err("launch_grant must fail");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err
            .1
            .contains("supervisor launch config must not carry launch_grant"));
    }

    #[test]
    fn supervisor_launch_allows_runtime_reserved_config() {
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "config": {
                "_elastos_interactive": true,
                "_elastos_capsule_args": ["--demo"]
            }
        }));

        supervisor_launch_principal_from_input(None, &input)
            .expect("runtime reserved config should pass");
    }

    #[test]
    fn supervisor_launch_accepts_signed_launch_grant() {
        let dir = tempfile::tempdir().unwrap();
        let context = crate::api::gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            crate::api::gateway::issue_home_launch_token_with_context(dir.path(), "chat", &context)
                .unwrap();
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "launch_grant": grant
        }));

        let principal = supervisor_launch_principal_from_input(Some(dir.path()), &input).unwrap();

        assert_eq!(
            principal
                .as_ref()
                .map(crate::resource_bridge::BridgePrincipal::principal_str),
            Some(context.principal_id())
        );
    }

    #[test]
    fn supervisor_launch_rejects_wrong_app_grant() {
        let dir = tempfile::tempdir().unwrap();
        let context = crate::api::gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant = crate::api::gateway::issue_home_launch_token_with_context(
            dir.path(),
            "documents",
            &context,
        )
        .unwrap();
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "launch_grant": grant
        }));

        let err = supervisor_launch_principal_from_input(Some(dir.path()), &input).unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("not authorized"));
    }

    /// R6-1 row r4: route 3 end to end through the HTTP handler
    /// (`supervisor_api::launch_capsule`), with a real `Supervisor` and the
    /// stored-human grant fixture. A valid person grant passes the agent
    /// refusal and the shell-launchable check as that person and reaches the
    /// release's microVM gate; a request with no grant passes it with no
    /// principal. The provider-role half is what observes the person rather
    /// than `None`: the typed principal reaches the role check, so the same
    /// request with no grant takes the other branch (both literals below).
    ///
    /// No part of this row depends on the agents build switch: the stored
    /// human grant path and the two refusals behave the same in both builds.
    /// The agent refusal itself is covered by its own gated row.
    #[tokio::test]
    async fn r6_launch_capsule_reaches_the_microvm_gate_with_the_typed_person() {
        use crate::setup::{CapsuleEntry, ComponentsManifest};

        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();
        for (name, cid, role) in [
            ("plain-vm-test", "bafy-plain-vm-test", "app"),
            ("provider-test", "bafy-provider-test", "provider"),
        ] {
            let capsule_dir = data_dir.join("capsules").join(name);
            std::fs::create_dir_all(&capsule_dir).unwrap();
            std::fs::write(capsule_dir.join(".elastos-cid"), format!("{cid}\n")).unwrap();
            std::fs::write(
                capsule_dir.join("capsule.json"),
                serde_json::json!({
                    "schema": "elastos.capsule/v1",
                    "name": name,
                    "version": "0.1.0",
                    "role": role,
                    "type": "microvm",
                    "entrypoint": "rootfs.ext4"
                })
                .to_string(),
            )
            .unwrap();
        }

        let mut capsules = std::collections::HashMap::new();
        for (name, cid) in [
            ("plain-vm-test", "bafy-plain-vm-test"),
            ("provider-test", "bafy-provider-test"),
        ] {
            capsules.insert(
                name.to_string(),
                CapsuleEntry {
                    extra: Default::default(),
                    cid: cid.to_string(),
                    sha256: String::new(),
                    size: 0,
                    repository: None,
                    platforms: vec![],
                },
            );
        }

        let supervisor = Supervisor::new(
            data_dir.to_path_buf(),
            ComponentsManifest {
                extra: Default::default(),
                model_catalog: None,
                collaboration_network: None,
                external: std::collections::HashMap::new(),
                capsules,
                profiles: std::collections::HashMap::new(),
            },
        );
        let state = SupervisorState {
            supervisor: Arc::new(supervisor),
            data_dir: Some(data_dir.to_path_buf()),
        };

        use elastos_runtime::auth::AuthSessionGrantV1;
        let now = crate::auth::now_ts();
        let record =
            crate::auth::store_test_human_principal(data_dir, "person:local:r6-supervisor");
        let session_grant = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: "grant:r6-supervisor".to_string(),
            session_id: "auth:r6-supervisor".to_string(),
            principal_id: record.principal_id.clone(),
            proof_binding_id: record.proof_binding_id.clone(),
            issued_at: now,
            expires_at: now + 600,
            apps: vec!["plain-vm-test".to_string(), "provider-test".to_string()],
        };
        crate::auth::store_session_grant(data_dir, session_grant.clone()).unwrap();
        let token_for = |app: &str| {
            crate::api::gateway::issue_home_launch_token_for_auth_grant(
                data_dir,
                app,
                &session_grant,
            )
            .unwrap()
        };

        let microvm_prefix = "launch_capsule failed: microVM capsules are not available on ";

        let with_person = launch_capsule(
            State(state.clone()),
            Json(launch_input(serde_json::json!({
                "name": "plain-vm-test",
                "launch_grant": token_for("plain-vm-test")
            }))),
        )
        .await
        .unwrap_err();
        assert_eq!(with_person.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            with_person.1.starts_with(microvm_prefix),
            "person grant reaches the microVM gate: {:?}",
            with_person.1
        );
        assert!(
            with_person
                .1
                .contains(". Cannot launch capsule 'plain-vm-test'."),
            "{:?}",
            with_person.1
        );

        let without_grant = launch_capsule(
            State(state.clone()),
            Json(launch_input(serde_json::json!({
                "name": "plain-vm-test"
            }))),
        )
        .await
        .unwrap_err();
        assert_eq!(without_grant.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            without_grant.1.starts_with(microvm_prefix),
            "a launch with no grant has no principal and reaches the same gate: {:?}",
            without_grant.1
        );
        assert!(
            without_grant
                .1
                .contains(". Cannot launch capsule 'plain-vm-test'."),
            "{:?}",
            without_grant.1
        );

        // The observable difference between the person and `None`: a
        // non-shell-launchable capsule refuses a principal, and the same
        // request without one falls through to the microVM gate.
        let provider_with_person = launch_capsule(
            State(state.clone()),
            Json(launch_input(serde_json::json!({
                "name": "provider-test",
                "launch_grant": token_for("provider-test")
            }))),
        )
        .await
        .unwrap_err();
        assert_eq!(
            provider_with_person.1,
            "launch_capsule failed: principal launch grants are only valid for shell-launchable capsules",
            "the typed person reaches the role check"
        );

        let provider_without_grant = launch_capsule(
            State(state),
            Json(launch_input(serde_json::json!({
                "name": "provider-test"
            }))),
        )
        .await
        .unwrap_err();
        assert!(
            provider_without_grant.1.starts_with(microvm_prefix),
            "no principal passes the role check: {:?}",
            provider_without_grant.1
        );
        assert!(
            provider_without_grant
                .1
                .contains(". Cannot launch capsule 'provider-test'."),
            "{:?}",
            provider_without_grant.1
        );
    }
}
