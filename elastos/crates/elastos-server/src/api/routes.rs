//! API route handlers

use std::sync::Arc;

use axum::{
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use elastos_runtime::primitives::audit::{AuditLog, TrustLevel};
use serde::{Deserialize, Serialize};

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
    let path = std::path::Path::new(&req.path);
    reject_raw_launch_principal_id(req.principal_id.as_deref())?;
    let (launcher, admission) = match req.agent_id.as_deref() {
        None => (
            principal_from_launch_request(
                data_dir.as_deref(),
                path,
                req.principal_id,
                req.launch_grant,
            )?,
            None,
        ),
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
            let launcher = principal_from_capsule_name(
                Some(data_dir),
                &walked.manifest.name,
                req.launch_grant,
            )?;
            let admission = admit_agent_launch(
                Some(data_dir),
                walked,
                launcher
                    .as_ref()
                    .map(crate::resource_bridge::BridgePrincipal::principal_str),
                agent_id,
            )?;
            (launcher, Some(admission))
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
        Some(admission) => runtime.start_local_admitted(path, vec![], admission).await,
        None => {
            runtime
                .start_local_with_signer(path, vec![], launcher)
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
            audit_log.capsule_launch(
                &handle.id.0,
                &handle.manifest.name,
                None,
                TrustLevel::Untrusted,
                signer_did,
            );
            Ok(Json(LaunchResponse {
                id: handle.id.0.clone(),
                name: handle.manifest.name,
                status: status.into(),
                session_id: handle.id.0,
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
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

/// A launch grant names the capsule it authorizes. For an agent launch that
/// name comes from the one walk, never from a second read of the folder.
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

fn principal_from_launch_request(
    data_dir: Option<&std::path::Path>,
    capsule_dir: &std::path::Path,
    principal_id: Option<String>,
    launch_grant: Option<String>,
) -> Result<Option<crate::resource_bridge::BridgePrincipal>, (StatusCode, String)> {
    reject_raw_launch_principal_id(principal_id.as_deref())?;
    let launch_grant = launch_grant
        .map(|grant| grant.trim().to_string())
        .filter(|grant| !grant.is_empty());
    if launch_grant.is_none() {
        return Ok(None);
    }
    if data_dir.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "principal launch grant unavailable".to_string(),
        ));
    }
    let capsule_name = launch_capsule_name(capsule_dir)?;
    principal_from_capsule_name(data_dir, &capsule_name, launch_grant)
}

fn launch_capsule_name(capsule_dir: &std::path::Path) -> Result<String, (StatusCode, String)> {
    let manifest_path = capsule_dir.join("capsule.json");
    let bytes = std::fs::read(&manifest_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("read capsule manifest for launch grant: {err}"),
        )
    })?;
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&bytes).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("parse capsule manifest for launch grant: {err}"),
            )
        })?;
    if manifest.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "capsule manifest name is required for launch grant".to_string(),
        ));
    }
    Ok(manifest.name)
}

pub async fn stop_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match runtime.stop_capsule_by_id(&id).await {
        Ok(true) => (StatusCode::OK, format!("Capsule {} stopped", id)),
        Ok(false) => (StatusCode::NOT_FOUND, format!("Capsule {} not found", id)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to stop capsule: {}", e),
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::gateway;
    use std::future::Future;

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
    fn launch_without_grant_stays_principal_less() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");

        let principal =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, None).unwrap();

        assert_eq!(principal, None);
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

    #[test]
    fn principal_launch_accepts_home_launch_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let principal =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, Some(grant))
                .unwrap();

        assert_eq!(
            principal
                .as_ref()
                .map(crate::resource_bridge::BridgePrincipal::principal_str),
            Some(context.principal_id())
        );
    }

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

    #[test]
    fn principal_launch_rejects_wrong_app_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
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
        let expected = "parse capsule manifest for launch grant: unknown field `cid`";
        assert!(err.1.starts_with(expected), "{}", err.1);
    }

    /// `POST /api/capsules` without a grant, for a pinned manifest: the
    /// request reaches the launch entry, whose parse refuses it. Nothing is
    /// launched, so no launch is written to the audit log.
    #[tokio::test]
    async fn a_launch_without_a_grant_stops_at_the_launch_entry_for_a_pinned_requirement() {
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
        let expected = "Invalid manifest: Failed to parse capsule.json: unknown field `cid`";
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
    struct CapturingModelProvider {
        requests: std::sync::Mutex<Vec<serde_json::Value>>,
        ceilings_at_call: std::sync::Mutex<Vec<Vec<(String, u64)>>>,
        runtime: std::sync::Mutex<Option<Arc<Runtime>>>,
    }

    impl CapturingModelProvider {
        fn requests(&self) -> Vec<serde_json::Value> {
            self.requests.lock().unwrap().clone()
        }

        fn watch(&self, runtime: Arc<Runtime>) {
            *self.runtime.lock().unwrap() = Some(runtime);
        }

        fn ceilings_at_call(&self) -> Vec<Vec<(String, u64)>> {
            self.ceilings_at_call.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
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
            Ok(serde_json::json!({"status": "ok", "data": {"ok": true}}))
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
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
        provider: Arc<CapturingLocalhostProvider>,
        capsule_dir: std::path::PathBuf,
        grant: String,
        pub(crate) agents: Vec<String>,
        /// The stored person every agent here belongs to. It is the person
        /// `agents::create` records in each agent's `owner`.
        owner: String,
    }

    const PROBE_HOST: &str = "a5-launch-probe";
    /// The package CID the install records; the launch compares the Runtime's own walk.
    const PROBE_REGISTRY_CID: &str = "bafkreia5probe";

    impl ProbeLaunch {
        pub(crate) async fn new(names: &[&str]) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let data_dir = temp.path().join("data");
            std::fs::create_dir_all(&data_dir).unwrap();
            let context = gateway::local_home_launch_token_context(&data_dir).unwrap();
            let owner = context.principal_id().to_string();
            crate::auth::store_test_principal_root_protection(&data_dir, &owner);
            crate::agents::tests::make_admin(&data_dir, &owner);
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
            )
            .await
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
            )
            .await
        }

        async fn build(
            temp: Option<tempfile::TempDir>,
            data_dir: std::path::PathBuf,
            owner: &str,
            proof_binding_id: &str,
            session_id: &str,
            context: &gateway::HomeLaunchTokenContext,
            names: &[&str],
        ) -> Self {
            use crate::agents;
            use elastos_compute::providers::ComponentProvider;
            use elastos_runtime::capability::{CapabilityManager, CapabilityStore};
            use elastos_runtime::primitives::metrics::MetricsManager;
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
            let capability_manager = Arc::new(CapabilityManager::new(
                Arc::new(CapabilityStore::new()),
                audit_log.clone(),
                Arc::new(MetricsManager::new()),
            ));
            let pending_store = Arc::new(
                elastos_runtime::capability::pending::PendingRequestStore::new(audit_log.clone()),
            );
            let provider = Arc::new(CapturingLocalhostProvider::default());
            let registry = Arc::new(ProviderRegistry::new());
            registry.register(provider.clone()).await;
            runtime
                .set_provider_registry(
                    registry,
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
            // The bytes are final. The stored host CID is the one walk the
            // Runtime makes of exactly these files; `.elastos-cid` is beside
            // them and takes no part in it.
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
                .collect();
            // A person's Home launch token is a projection under the Home
            // capsule's authority (`gateway_home_runtime.rs:149`), which is
            // the app the person's sign-in grant authorizes. The Runtime-local
            // fixture has no sign-in grant apps, so its direct token stays.
            let grant = match context.proof_binding_id() {
                Some(_) => gateway::issue_home_projection_launch_token_with_context(
                    &data_dir, PROBE_HOST, PROBE_HOST, context,
                ),
                None => {
                    gateway::issue_home_launch_token_with_context(&data_dir, PROBE_HOST, context)
                }
            }
            .unwrap();
            Self {
                _temp: temp,
                fixture_root,
                data_dir,
                runtime,
                audit_log,
                pending_store,
                capability_manager,
                provider,
                capsule_dir,
                grant,
                agents,
                owner: owner.to_string(),
            }
        }

        /// Writes a second signed Agent Host folder whose manifest adds
        /// `claims` to its capabilities, exactly as the stored host is
        /// written, and returns the folder and the CID the Runtime's walk
        /// gives it. The extra claims name another agent's root; admission
        /// still binds the agent the request names.
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
            agents::create(
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
            .agent_id
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
        pub(crate) async fn listed(&self) -> Vec<serde_json::Value> {
            let Json(list) = list_capsules(Extension(self.runtime.clone())).await;
            serde_json::to_value(&list).unwrap()["capsules"]
                .as_array()
                .expect("the list is an array")
                .clone()
        }

        /// The same launch from `dir`, which must walk to the bytes the agent's
        /// stored Agent Host names.
        fn launch_from<'a>(
            &'a self,
            dir: &'a std::path::Path,
            agent_id: &'a str,
        ) -> impl Future<Output = Result<Json<LaunchResponse>, (StatusCode, String)>> + 'a {
            let grant = self.grant.clone();
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
        pub(crate) fn requests(&self) -> Vec<serde_json::Value> {
            self.provider.requests()
        }

        /// Every `CapabilityRequested` event's resource, in order. A request
        /// the bridge refuses before creating a record never appears here, so
        /// a refused spelling's absence is evidence it reached no store.
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
    /// did not change.
    pub(crate) fn tree_hashes(dir: &std::path::Path) -> Vec<(String, String)> {
        use sha2::{Digest, Sha256};
        fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(root, &path, out);
                } else {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    let bytes = std::fs::read(&path).unwrap();
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
        // and cause, and a stop finds nothing left to stop. A new launch takes
        // the same principal and root, and its guest reads back both files the
        // earlier launch wrote.
        assert!(!home.runtime.stop_capsule_by_id(&first.id).await.unwrap());
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

    /// A3-R proof row. Two agents of one Home are resident at once through the
    /// production launch route. A's launch returns while its guest runs, held
    /// in its own first bridge call; B's launch returns while A is still
    /// running. Two registry entries are `running` with distinct id, session
    /// and principal, and both end `stopped` with cause `completed` after
    /// their calls are granted.
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

    /// The launch answers `starting` with its session while its guest runs; the
    /// entry is `running` from the moment the worker reports `started` until the
    /// guest ends.
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

    /// An ended entry is listed for the 60 s retention and is gone after it,
    /// read at a caller's instant rather than waited for.
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

    /// Row 2, refusal: agent X's own guest asks for agent Y's file by Y's
    /// stored root. The bridge refuses the request, nothing under Y's root is
    /// read or audited for X, and X's activation ends `failed` with that
    /// refusal as its cause.
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
            principal_id: Some(x.clone()),
            manifest_capabilities: Vec::new(),
            data_dir: Some(home.data_dir.clone()),
            launch: None,
            model_token_ceiling: None,
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
    const A9R_SCOPE: &str =
        "localhost://UsersAI roots must use UsersAI/self or the active principal root";

    /// The three files A keeps under its own `UsersAI` root in the A9-R rows:
    /// the agent's format-2 journal, its `memory/notes.md`, and one ordinary
    /// file that is neither journal nor memory.
    fn a9r_own_uris(root: &str) -> (String, String, String) {
        (
            format!("{root}/.AppData/Agents/agent-host/tasks/t1/journal"),
            format!("{root}/memory/notes.md"),
            format!("{root}/notes/alpha.txt"),
        )
    }

    /// Writes A's three files the way production writes a principal-root
    /// object, so each has real bytes before either agent launches.
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
    struct A9rRow {
        home: ProbeLaunch,
        a: String,
        b: String,
        b_host: std::path::PathBuf,
        root_a: String,
        own: (String, String, String),
    }

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

        let context = gateway::local_home_launch_token_context(&data_dir).unwrap();
        let owner = context.principal_id().to_string();
        crate::auth::store_test_principal_root_protection(&data_dir, &owner);
        crate::agents::tests::make_admin(&data_dir, &owner);
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

        // The forged capsule: the stored manifest name and the stored CID in
        // its own `.elastos-cid`, signed by a trusted key, over other code.
        let forged_dir = temp.path().join("forged-probe");
        std::fs::create_dir_all(&forged_dir).unwrap();
        let other_wasm =
            std::fs::read(fixtures.join("bus-v1/bus-v1-conformance.component.wasm")).unwrap();
        sign(&forged_dir, "forged.component.wasm", &other_wasm);
        std::fs::write(forged_dir.join(".elastos-cid"), format!("{stored_cid}\n")).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(&data_dir, PROBE_HOST, &context).unwrap();

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
    #[tokio::test]
    async fn an_agent_launch_refuses_a_grant_for_another_capsule() {
        if crate::agents::require_build().is_err() {
            return;
        }
        let home = ProbeLaunch::new(&["a"]).await;
        let agent = home.agents.first().expect("one agent").clone();
        let context = gateway::local_home_launch_token_context(&home.data_dir).unwrap();
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

    /// Round 3, point 3: a record written before the Runtime stored the Agent
    /// Host's byte CID still loads through the real strict parser, and every
    /// launch of it is refused by name. The missing CID is never re-derived
    /// from `.elastos-cid` or from the release record.
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

    /// An admitted agent whose signed manifest asks for no model tokens cannot
    /// reach the model. The provider records no call.
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
    let person = super::gateway::require_internal_shell_launch_grant_for_any_context(
        &data_dir,
        &headers,
        &[super::gateway::HOME_CAPSULE_ID],
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    match runtime
        .open_for_page(&data_dir, &req.cid, person.principal_id())
        .await
    {
        Ok(opened) => Ok(Json(OpenLaunchResponse {
            id: opened.id,
            page: opened.page,
            entrypoint: opened.entrypoint,
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
/// `elastos://launch/<id>` with the page the launch was kept for as its
/// executable, gives the person. Nothing else does.
fn kept_launch_reader(
    runtime: &Runtime,
    data_dir: Option<&std::path::Path>,
    headers: &HeaderMap,
    id: &str,
) -> Option<(String, String)> {
    let page = runtime.kept_launch_page(id)?;
    let bound = format!("elastos://launch/{id}");
    let token = super::gateway::require_internal_shell_projection_context(
        data_dir?, headers, &bound, &page,
    )
    .ok()?;
    Some((token.principal_id().to_string(), page))
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
    let read = kept_launch_reader(&runtime, data_dir.as_deref(), &headers, &id).and_then(
        |(person, page)| {
            let what = crate::page_launch::KeptRead::Output(&name);
            runtime.read_kept_launch(&id, &person, &page, what)
        },
    );
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
    let read = kept_launch_reader(&runtime, data_dir.as_deref(), &headers, &id).and_then(
        |(person, page)| {
            let what = crate::page_launch::KeptRead::Content(&path);
            runtime.read_kept_launch(&id, &person, &page, what)
        },
    );
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
    pub(crate) fn home(data_dir: &std::path::Path) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        super::super::gateway::issue_home_launch_token_with_context(data_dir, "home", &context)
            .unwrap()
    }

    /// A page's token bound to `resource`, with `page` as its executable.
    pub(crate) fn page(data_dir: &std::path::Path, resource: &str, page: &str) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        super::super::gateway::issue_home_projection_launch_token_with_context(
            data_dir, resource, page, &context,
        )
        .unwrap()
    }

    /// The person these tokens are for.
    pub(crate) fn person(data_dir: &std::path::Path) -> String {
        let context = super::super::gateway::local_home_launch_token_context(data_dir).unwrap();
        context.principal_id().to_string()
    }
}
