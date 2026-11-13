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
}

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
        })
        .collect();

    Json(CapsuleListResponse { capsules })
}

/// Unknown fields are refused: a launch request carries no principal kind. The
/// agent kind is read only from the signed manifest at admission (F-A5-kind).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    path: String,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    launch_grant: Option<String>,
}

#[derive(Serialize)]
pub struct LaunchResponse {
    id: String,
    name: String,
    status: String,
}

pub async fn launch_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(audit_log): Extension<Arc<AuditLog>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    Json(req): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
    let path = std::path::Path::new(&req.path);
    let principal_id = principal_from_launch_request(
        data_dir.as_deref(),
        path,
        req.principal_id,
        req.launch_grant,
    )?;

    match runtime
        .run_local_with_signer(path, vec![], principal_id)
        .await
    {
        Ok((handle, signer)) => {
            let status = if handle.manifest.is_component_capsule() {
                "completed"
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
                id: handle.id.0,
                name: handle.manifest.name,
                status: status.into(),
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

fn reject_raw_launch_principal_id(
    principal_id: Option<String>,
) -> Result<(), (StatusCode, String)> {
    if principal_id
        .as_deref()
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

fn principal_from_launch_request(
    data_dir: Option<&std::path::Path>,
    capsule_dir: &std::path::Path,
    principal_id: Option<String>,
    launch_grant: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    reject_raw_launch_principal_id(principal_id)?;
    let launch_grant = launch_grant
        .map(|grant| grant.trim().to_string())
        .filter(|grant| !grant.is_empty());
    match launch_grant {
        None => Ok(None),
        Some(grant) => {
            let data_dir = data_dir.ok_or((
                StatusCode::BAD_REQUEST,
                "principal launch grant unavailable".to_string(),
            ))?;
            let capsule_name = launch_capsule_name(capsule_dir)?;
            let mut headers = HeaderMap::new();
            let header_value = HeaderValue::from_str(&grant).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid launch_grant header value".to_string(),
                )
            })?;
            headers.insert("x-elastos-home-token", header_value);
            let context = super::gateway::require_internal_shell_launch_grant_for_any_context(
                data_dir,
                &headers,
                &[capsule_name.as_str()],
            )
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok(Some(context.principal_id().to_string()))
        }
    }
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
mod tests {
    use super::*;
    use crate::api::gateway;

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

        assert_eq!(principal.as_deref(), Some(context.principal_id()));
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
        })),
        Err(OpenRefusal::Start(refusal)) => Err((
            StatusCode::BAD_REQUEST,
            format!("{}: {refusal}", refusal.code()),
        )),
        Err(OpenRefusal::NotContent) => Err((StatusCode::BAD_REQUEST, "not_content".into())),
        Err(OpenRefusal::TooManyOpen) => Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_open_launches".into(),
        )),
        Err(OpenRefusal::NoPrincipal) => Err((StatusCode::UNAUTHORIZED, "no_principal".into())),
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
