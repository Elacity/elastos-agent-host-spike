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
            let admission =
                admit_agent_launch(Some(data_dir), walked, launcher.as_deref(), agent_id)?;
            (launcher, Some(admission))
        }
    };
    // An admitted agent launch starts through the one entry that may hand the
    // bridge an agent's own id, and from the bytes admission walked. Every
    // other launch is exactly as it was.
    let started = match admission {
        Some(admission) => runtime.run_local_admitted(path, vec![], admission).await,
        None => runtime.run_local_with_signer(path, vec![], launcher).await,
    };

    match started {
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
) -> Result<Option<String>, (StatusCode, String)> {
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
    let context = super::gateway::require_internal_shell_launch_grant_for_any_context(
        data_dir,
        &headers,
        &[capsule_name],
    )
    .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    Ok(Some(context.principal_id().to_string()))
}

fn principal_from_launch_request(
    data_dir: Option<&std::path::Path>,
    capsule_dir: &std::path::Path,
    principal_id: Option<String>,
    launch_grant: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
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

    /// A Home whose stored agents are the probe package: the probe's manifest
    /// name and the CID its capsule directory records, signed by a key the
    /// runtime trusts. Two agents, or as many as asked for, share the Home.
    struct ProbeLaunch {
        _temp: tempfile::TempDir,
        data_dir: std::path::PathBuf,
        runtime: Arc<Runtime>,
        audit_log: Arc<AuditLog>,
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
        capsule_dir: std::path::PathBuf,
        grant: String,
        agents: Vec<String>,
    }

    const PROBE_HOST: &str = "a5-launch-probe";
    /// The package CID the install records; the launch compares the Runtime's own walk.
    const PROBE_REGISTRY_CID: &str = "bafkreia5probe";

    impl ProbeLaunch {
        async fn new(names: &[&str]) -> Self {
            use crate::agents;
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
            runtime
                .set_provider_registry(
                    Arc::new(ProviderRegistry::new()),
                    capability_manager.clone(),
                    pending_store.clone(),
                    data_dir.clone(),
                )
                .await;

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
                session_id: "session:a5-launch",
            };
            agents::set_enabled(&data_dir, &caller, true, 1).unwrap();

            let capsule_dir = temp.path().join(PROBE_HOST);
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
            let grant =
                gateway::issue_home_launch_token_with_context(&data_dir, PROBE_HOST, &context)
                    .unwrap();
            Self {
                _temp: temp,
                data_dir,
                runtime,
                audit_log,
                pending_store,
                capability_manager,
                capsule_dir,
                grant,
                agents,
            }
        }

        fn root(&self, agent_id: &str) -> String {
            crate::auth::principal_stored_localhost_root(Some(&self.data_dir), agent_id).unwrap()
        }

        fn launch(
            &self,
            agent_id: &str,
        ) -> impl std::future::Future<Output = Result<Json<LaunchResponse>, (StatusCode, String)>> + '_
        {
            launch_capsule(
                Extension(self.runtime.clone()),
                Extension(self.audit_log.clone()),
                Extension(Some(self.data_dir.clone())),
                Json(LaunchRequest {
                    path: self.capsule_dir.to_string_lossy().into_owned(),
                    principal_id: None,
                    launch_grant: Some(self.grant.clone()),
                    agent_id: Some(agent_id.to_string()),
                }),
            )
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
    }

    /// Grants every pending capability request the probe makes, as the shell
    /// would, and keeps doing it until the test stops the task.
    fn grant_probe_requests(
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
    /// `memory/notes.md` through the bridge, reads both back, and the launch
    /// completes only when the bytes return. Each bridge call is audited under
    /// that agent's own id and root, and the same holds after a stop and
    /// relaunch. Row 6b rides here too: the manifest declares the agent kind
    /// and names no id, and the audited actor is still the id the request named.
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
        assert_eq!(first.status, "completed");
        assert_eq!(second.status, "completed");

        // Each bridge call names that agent and its own capsule instance, and
        // carries the concrete URI the guest asked for through `UsersAI/self`.
        let own_calls = |root: &str, session: &str| {
            vec![
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    format!("write {root}/.AppData/Agents/agent-host/tasks/t1/journal"),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    format!("write {root}/memory/notes.md"),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    format!("read {root}/.AppData/Agents/agent-host/tasks/t1/journal"),
                ),
                (
                    Some(session.to_string()),
                    "ok".to_string(),
                    format!("read {root}/memory/notes.md"),
                ),
            ]
        };
        let peer_miss = |root: &str, session: &str| {
            (
                Some(session.to_string()),
                "error".to_string(),
                format!("read {root}/memory/peer"),
            )
        };
        let (root_a, root_b) = (home.root(a), home.root(b));
        assert_ne!(root_a, root_b);
        assert!(root_a.starts_with("localhost://UsersAI/"), "{root_a}");
        assert!(root_b.starts_with("localhost://UsersAI/"), "{root_b}");

        let mut expected_a = own_calls(&root_a, &first.id);
        expected_a.push(peer_miss(&root_a, &first.id));
        let mut expected_b = own_calls(&root_b, &second.id);
        expected_b.push(peer_miss(&root_b, &second.id));
        assert_eq!(home.invoked(a), expected_a);
        assert_eq!(home.invoked(b), expected_b);

        // The one-shot component has ended, so a stop finds nothing; a new
        // launch takes the same principal and root, and its guest reads back
        // both files the earlier launch wrote.
        assert!(!home.runtime.stop_capsule_by_id(&first.id).await.unwrap());
        let again = home.launch(a).await.unwrap().0;
        assert_ne!(again.id, first.id);
        assert_eq!(home.root(a), root_a);
        let mut relaunched = own_calls(&root_a, &again.id);
        relaunched.push(peer_miss(&root_a, &again.id));
        let mut all = expected_a;
        all.extend(relaunched);
        assert_eq!(home.invoked(a), all);
        assert_eq!(
            home.invoked(b).len(),
            5,
            "the other agent's calls are untouched"
        );
        grants.abort();
    }

    /// Row 2, refusal: agent X's own guest asks for agent Y's file by Y's
    /// stored root. The bridge refuses the request, nothing under Y's root is
    /// read or audited for X, and X's launch reports that refusal.
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
        assert_eq!(y_run.status, "completed");
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

        let response = home.launch(x).await;
        let (status, message) = match response {
            Ok(_) => panic!("a read outside the agent's own root was allowed"),
            Err(error) => error,
        };
        assert_eq!(status, StatusCode::BAD_REQUEST);
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
        assert_eq!(invoked[4].2, format!("read {pointer_uri}"));
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
                && reason == &format!("write {root_y}/memory/notes.md")));
        grants.abort();
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
