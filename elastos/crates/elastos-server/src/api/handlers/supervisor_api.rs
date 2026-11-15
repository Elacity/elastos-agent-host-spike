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
    /// The guest payload, moved whole to the guest. The host does not read it;
    /// the wire name stays `config`.
    #[serde(default, rename = "config")]
    pub guest_payload: serde_json::Value,
    /// Guest stdio: a shell-launched capsule that needs a terminal.
    #[serde(default)]
    pub interactive: bool,
    /// Arguments forwarded to the capsule entrypoint by the guest init.
    #[serde(default)]
    pub capsule_args: Vec<String>,
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
    let req = supervisor_launch_request(input, principal_id);
    let resp = state.supervisor.handle_request(req).await;
    if resp.status != "ok" {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            resp.error.unwrap_or_else(|| "unknown error".into()),
        ));
    }
    Ok(Json(resp.into()))
}

/// The supervisor request the HTTP handler builds. A plain constructor, so a
/// test can hold the request the handler hands the supervisor without a hook
/// on the security path.
fn supervisor_launch_request(
    input: LaunchCapsuleInput,
    principal_id: Option<crate::resource_bridge::BridgePrincipal>,
) -> SupervisorRequest {
    SupervisorRequest::LaunchCapsule {
        name: input.name,
        guest_payload: input.guest_payload,
        interactive: input.interactive,
        capsule_args: input.capsule_args,
        principal_id,
    }
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

    if let Some(guest_payload) = input.guest_payload.as_object() {
        for key in SUPERVISOR_PRINCIPAL_AUTHORITY_KEYS {
            if guest_payload.contains_key(*key) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "supervisor launch config must not carry {key}; use the signed Home launch-grant path"
                    ),
                ));
            }
        }
        // Compatibility refusal, not an authority rule: a payload that still
        // carries a top-level `_elastos_` key was written for the old host-key
        // spelling. The host keys are typed fields now, so an old sender fails
        // closed here instead of handing a host key to the guest (r5 §3 M6).
        if let Some(key) = guest_payload
            .keys()
            .find(|key| key.starts_with("_elastos_"))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "launch_config_reserved_key: supervisor launch config must not carry {key}"
                ),
            ));
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

    /// a2/a4 (R6-2a): the old `_elastos_` spelling is refused at the entrance.
    /// This test inverts `supervisor_launch_allows_runtime_reserved_config`,
    /// which asserted the same two keys passed before the host keys became
    /// typed fields. Any other top-level key in that namespace is refused too.
    #[test]
    fn supervisor_launch_refuses_reserved_config_keys() {
        for key in [
            "_elastos_interactive",
            "_elastos_capsule_args",
            "_elastos_x",
        ] {
            let mut config = serde_json::Map::new();
            config.insert(key.to_string(), serde_json::json!(true));
            let input = launch_input(serde_json::json!({
                "name": "chat",
                "config": config
            }));

            let err = supervisor_launch_principal_from_input(None, &input)
                .expect_err("a reserved config key must fail");
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert!(
                err.1.contains("launch_config_reserved_key"),
                "{key}: {:?}",
                err.1
            );
            assert!(err.1.contains(key), "{key}: {:?}", err.1);
        }
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

    fn test_state(data_dir: &std::path::Path) -> SupervisorState {
        use crate::setup::ComponentsManifest;
        let supervisor = Supervisor::new(
            data_dir.to_path_buf(),
            ComponentsManifest {
                extra: Default::default(),
                model_catalog: None,
                collaboration_network: None,
                external: std::collections::HashMap::new(),
                capsules: std::collections::HashMap::new(),
                profiles: std::collections::HashMap::new(),
            },
        );
        SupervisorState {
            supervisor: Arc::new(supervisor),
            data_dir: Some(data_dir.to_path_buf()),
        }
    }

    async fn post_launch(app: axum::Router, body: serde_json::Value) -> (StatusCode, String) {
        use tower::ServiceExt as _;
        let request = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/supervisor/launch-capsule")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    fn launch_router(state: SupervisorState) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/supervisor/launch-capsule",
                axum::routing::post(launch_capsule),
            )
            .with_state(state)
    }

    /// a1 (R6-2a): the HTTP handler hands the supervisor `interactive` and
    /// `capsule_args` from the typed fields. This captures the built
    /// `SupervisorRequest` through the handler's own constructor
    /// (`supervisor_launch_request`, the only place the handler builds one);
    /// this Mac reaches no VM, so a boot-arg assertion cannot observe them
    /// end to end. The body's guest config moves unchanged.
    #[test]
    fn r6_2a_the_launch_request_carries_the_typed_fields() {
        let input = launch_input(serde_json::json!({
            "name": "chat",
            "config": {"nick": "alice"},
            "interactive": true,
            "capsule_args": ["--demo", "a b"]
        }));
        match supervisor_launch_request(input, None) {
            SupervisorRequest::LaunchCapsule {
                name,
                guest_payload,
                interactive,
                capsule_args,
                principal_id,
            } => {
                assert_eq!(name, "chat");
                assert_eq!(guest_payload, serde_json::json!({"nick": "alice"}));
                assert!(
                    interactive,
                    "the typed interactive field reaches the request"
                );
                assert_eq!(
                    capsule_args,
                    vec!["--demo".to_string(), "a b".to_string()],
                    "the typed capsule_args reach the request"
                );
                assert!(principal_id.is_none());
            }
            _ => panic!("wrong variant"),
        }

        // Old bodies carry neither field and keep parsing with defaults.
        match supervisor_launch_request(launch_input(serde_json::json!({"name": "chat"})), None) {
            SupervisorRequest::LaunchCapsule {
                interactive,
                capsule_args,
                ..
            } => {
                assert!(!interactive);
                assert!(capsule_args.is_empty());
            }
            _ => panic!("wrong variant"),
        }
    }

    /// a2 (R6-2a): a config object with any top-level `_elastos_` key is
    /// refused by name at the real HTTP entrance, before the request is built,
    /// so nothing is launched. The old spelling fails closed.
    #[tokio::test]
    async fn r6_2a_a_reserved_config_key_is_refused_at_the_entrance() {
        let dir = tempfile::tempdir().unwrap();
        let app = launch_router(test_state(dir.path()));
        for (key, body) in [
            (
                "_elastos_interactive",
                serde_json::json!({"name": "chat", "config": {"_elastos_interactive": true}}),
            ),
            (
                "_elastos_capsule_args",
                serde_json::json!({"name": "chat", "config": {"_elastos_capsule_args": ["--demo"]}}),
            ),
            (
                "_elastos_x",
                serde_json::json!({"name": "chat", "config": {"_elastos_x": 1}}),
            ),
        ] {
            let (status, text) = post_launch(app.clone(), body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{key}");
            assert!(text.contains("launch_config_reserved_key"), "{key}: {text}");
            assert!(text.contains(key), "{key}: {text}");
            assert!(
                !text.contains("Cannot launch capsule"),
                "the refusal precedes any launch: {text}"
            );
        }
    }

    /// a3 (R6-2a): a non-string `capsule_args` element and a non-bool
    /// `interactive` are refused by axum's JSON extractor before the handler
    /// runs. The exact status is 422 Unprocessable Entity (a data error, not a
    /// syntax error). Nothing is launched because the handler never runs.
    #[tokio::test]
    async fn r6_2a_a_bad_typed_field_is_refused_at_deserialisation() {
        let dir = tempfile::tempdir().unwrap();
        let app = launch_router(test_state(dir.path()));
        for body in [
            serde_json::json!({"name": "chat", "capsule_args": [1]}),
            serde_json::json!({"name": "chat", "interactive": "yes"}),
        ] {
            let (status, _) = post_launch(app.clone(), body.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "axum's JSON data error: {body}"
            );
        }
    }

    /// G3a-1 option (i) (r6 §0, r5 §2; facts §5): an agent-shaped guest payload
    /// in a person's verified launch reaches the release's microVM gate as the
    /// PERSON, not as the agent, and nothing at the stored agent's root is
    /// read, written or returned. The row drives the real HTTP handler with a
    /// real `Supervisor` and a stored agent whose root holds real bytes.
    ///
    /// Feature-on only: with the feature off the agent refusal is a no-op, so
    /// the planted handler could not change this row's literal. It is skipped
    /// by name in that build.
    #[tokio::test]
    async fn r6_2b_an_agent_shaped_payload_launches_as_the_person_and_touches_no_agent_root() {
        let Some((home, agents)) =
            crate::agents::tests::home_with_agents_if_built(1, "bafkreia5probe")
        else {
            assert!(!crate::agents::build_allows());
            eprintln!(
                "SKIP r6_2b_an_agent_shaped_payload_launches_as_the_person_and_touches_no_agent_root: \
                 this build carries no agents (prototype-agents off)"
            );
            return;
        };
        let agent = agents.into_iter().next().unwrap();
        let data_dir = home.path();

        use crate::setup::{CapsuleEntry, ComponentsManifest};
        let capsule_dir = data_dir.join("capsules/plain-vm-test");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(capsule_dir.join(".elastos-cid"), "bafy-plain-vm-test\n").unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::json!({
                "schema": "elastos.capsule/v1",
                "name": "plain-vm-test",
                "version": "0.1.0",
                "role": "app",
                "type": "microvm",
                "entrypoint": "rootfs.ext4"
            })
            .to_string(),
        )
        .unwrap();

        let mut capsules = std::collections::HashMap::new();
        capsules.insert(
            "plain-vm-test".to_string(),
            CapsuleEntry {
                extra: Default::default(),
                cid: "bafy-plain-vm-test".to_string(),
                sha256: String::new(),
                size: 0,
                repository: None,
                platforms: vec![],
            },
        );
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
        let record = crate::auth::store_test_human_principal(data_dir, "person:local:r6-2b");
        let session_grant = AuthSessionGrantV1 {
            schema: AuthSessionGrantV1::SCHEMA.to_string(),
            grant_id: "grant:r6-2b".to_string(),
            session_id: "auth:r6-2b".to_string(),
            principal_id: record.principal_id.clone(),
            proof_binding_id: record.proof_binding_id.clone(),
            issued_at: now,
            expires_at: now + 600,
            apps: vec!["plain-vm-test".to_string()],
        };
        crate::auth::store_session_grant(data_dir, session_grant.clone()).unwrap();
        let grant = crate::api::gateway::issue_home_launch_token_for_auth_grant(
            data_dir,
            "plain-vm-test",
            &session_grant,
        )
        .unwrap();

        // Real data where the agent's id rule points, and the agent file.
        let root =
            crate::auth::principal_kind_localhost_root(&agent, crate::auth::PrincipalKind::Agent);
        let root_dir =
            elastos_common::localhost::rooted_localhost_fs_path(data_dir, &root).unwrap();
        std::fs::create_dir_all(&root_dir).unwrap();
        let secret = root_dir.join("secret.txt");
        std::fs::write(&secret, b"agent-root-secret").unwrap();
        let secret_before = std::fs::read(&secret).unwrap();
        let secret_mtime = std::fs::metadata(&secret).unwrap().modified().unwrap();
        let agent_file = crate::agents::agent_file_path(data_dir).unwrap();
        let agent_before = std::fs::read(&agent_file).unwrap();

        let error = launch_capsule(
            State(state),
            Json(launch_input(serde_json::json!({
                "name": "plain-vm-test",
                "launch_grant": grant,
                "config": {
                    "agent_id": agent,
                    "agent": {"kind": "agent"},
                    "principal": {"id": agent},
                }
            }))),
        )
        .await
        .unwrap_err();

        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            error
                .1
                .starts_with("launch_capsule failed: microVM capsules are not available on "),
            "the launch passed the agent gate as the person: {:?}",
            error.1
        );
        assert!(
            !error
                .1
                .contains(crate::agent_admission::UNADMITTED_AGENT_PRINCIPAL),
            "the payload's agent id is not the principal: {:?}",
            error.1
        );
        assert!(
            !error.1.contains("agent-root-secret"),
            "nothing from the agent root is returned: {:?}",
            error.1
        );
        assert_eq!(
            std::fs::read(&secret).unwrap(),
            secret_before,
            "the agent root is not written"
        );
        assert_eq!(
            std::fs::metadata(&secret).unwrap().modified().unwrap(),
            secret_mtime,
            "the agent root file is untouched"
        );
        assert_eq!(
            std::fs::read(&agent_file).unwrap(),
            agent_before,
            "the agent file is not rewritten"
        );
    }
}
