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
    let launcher = principal_from_launch_request(
        data_dir.as_deref(),
        path,
        req.principal_id,
        req.launch_grant,
    )?;
    let admission = match req.agent_id.as_deref() {
        None => None,
        Some(agent_id) => Some(admit_agent_launch(
            data_dir.as_deref(),
            path,
            launcher.as_deref(),
            agent_id,
        )?),
    };
    // An admitted agent launch starts through the one entry that may hand the
    // bridge an agent's own id. Every other launch is exactly as it was.
    let started = match &admission {
        Some(admission) => {
            runtime
                .run_local_admitted(path, vec![], &admission.actor)
                .await
        }
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
    capsule_dir: &std::path::Path,
    launcher: Option<&str>,
    agent_id: &str,
) -> Result<crate::agent_admission::AdmissionContext, (StatusCode, String)> {
    let bytes = std::fs::read(capsule_dir.join("capsule.json")).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("read capsule manifest for an agent launch: {err}"),
        )
    })?;
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&bytes).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("parse capsule manifest for an agent launch: {err}"),
            )
        })?;
    if manifest.agent.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "this capsule does not declare an agent, so no stored agent runs it".to_string(),
        ));
    }
    let data_dir = data_dir.ok_or((
        StatusCode::BAD_REQUEST,
        "an agent launch needs this Home's data directory".to_string(),
    ))?;
    let sign_in_store = super::gateway::home_launch_auth_data_dir(data_dir);
    crate::agent_admission::admit_launch(data_dir, &sign_in_store, launcher, Some(agent_id))
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?
        .ok_or((
            StatusCode::BAD_REQUEST,
            "an agent launch needs a stored agent".to_string(),
        ))
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

    /// A5 admission row 1, at the launch entry with the feature on: two stored
    /// agents of one owner launch through `launch_capsule` with dev mode off.
    /// Each bridge call is audited under that agent's own id, each agent lands
    /// a journal and `memory/notes.md` under its own `UsersAI` root, and the
    /// same pair holds after a stop and relaunch. Row 6b rides here too: the
    /// capsule's manifest names no agent, and the audited actor is still the id
    /// the request named.
    #[tokio::test]
    async fn an_agent_launch_binds_each_agents_own_principal_and_root() {
        use crate::agents;
        if crate::agents::require_build().is_err() {
            return;
        }
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
                capability_manager,
                pending_store,
                data_dir.clone(),
            )
            .await;

        // The owner is the local device principal: a person record with an
        // admin role and its own root protection, as a Home keeps one.
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
        let create = |name: &str| {
            agents::create(
                &data_dir,
                &caller,
                &agents::CreateRequest {
                    display_name: name.to_string(),
                    agent_host: "agent-host".to_string(),
                    request_id: format!("request-{name}"),
                },
                |host| {
                    Ok(
                        crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                            host,
                            "bafyagenthost",
                        ),
                    )
                },
                1,
            )
            .unwrap()
            .agent_id
        };
        let (a, b) = (create("a"), create("b"));

        // The probe capsule is signed by the trusted key above, and its
        // manifest names no agent: only the request does.
        let capsule_dir = temp.path().join("a5-launch-probe");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/a5-launch-probe");
        for file in ["capsule.json", "a5-launch-probe.component.wasm"] {
            std::fs::copy(fixture.join(file), capsule_dir.join(file)).unwrap();
        }
        let wasm = std::fs::read(capsule_dir.join("a5-launch-probe.component.wasm")).unwrap();
        let mut manifest: elastos_common::CapsuleManifest =
            serde_json::from_slice(&std::fs::read(capsule_dir.join("capsule.json")).unwrap())
                .unwrap();
        assert_eq!(
            manifest.agent,
            Some(elastos_common::AgentDeclaration {
                kind: elastos_common::AgentKind::Agent
            }),
            "the manifest declares an agent and names no id of its own"
        );
        sign_capsule(&key, &mut manifest, &hash_content(&wasm)).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(&data_dir, "a5-launch-probe", &context)
                .unwrap();

        let launch = |agent_id: &str| {
            launch_capsule(
                Extension(runtime.clone()),
                Extension(audit_log.clone()),
                Extension(Some(data_dir.clone())),
                Json(LaunchRequest {
                    path: capsule_dir.to_string_lossy().to_string(),
                    principal_id: None,
                    launch_grant: Some(grant.clone()),
                    agent_id: Some(agent_id.to_string()),
                }),
            )
        };
        let first = launch(&a).await.unwrap().0;
        let second = launch(&b).await.unwrap().0;

        // Each bridge call names that agent and its own capsule instance.
        let invoked = |agent_id: &str| {
            crate::auth::load_auth_state(&data_dir)
                .unwrap()
                .audit
                .iter()
                .filter(|event| event.event_type == "component.invoke.completed")
                .filter(|event| event.principal_id.as_deref() == Some(agent_id))
                .map(|event| (event.session_id.clone(), event.reason.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            invoked(&a),
            [(
                Some(first.id.clone()),
                "read elastos://test/bus/probe".to_string()
            )]
        );
        assert_eq!(
            invoked(&b),
            [(
                Some(second.id.clone()),
                "read elastos://test/bus/probe".to_string()
            )]
        );

        // Two principals, two roots.
        let root = |agent_id: &str| {
            crate::auth::principal_stored_localhost_root(Some(&data_dir), agent_id).unwrap()
        };
        let (root_a, root_b) = (root(&a), root(&b));
        assert_ne!(root_a, root_b);
        assert!(root_a.starts_with("localhost://UsersAI/"), "{root_a}");
        assert!(root_b.starts_with("localhost://UsersAI/"), "{root_b}");

        // Row 2, positive placement: each agent writes a format-2 journal
        // entry and `memory/notes.md` under its own root, in its own key, and
        // each reads both back after the relaunch below. The journal body
        // starts as the Agent Host writes it: magic, then format 2.
        let journal = |agent_id: &str| {
            let mut body = b"EAHJ".to_vec();
            body.extend_from_slice(&2u16.to_le_bytes());
            body.extend_from_slice(agent_id.as_bytes());
            body
        };
        let note_uris = |root: &str| {
            [
                format!("{root}/.AppData/Agents/agent-host/tasks/t1/journal"),
                format!("{root}/memory/notes.md"),
            ]
        };
        let notes = [(&a, &root_a, journal(&a)), (&b, &root_b, journal(&b))];
        let placed = |agent_root: &str| {
            note_uris(agent_root)
                .into_iter()
                .map(|uri| {
                    let path = elastos_common::localhost::rooted_localhost_fs_path(&data_dir, &uri)
                        .unwrap();
                    (uri, path)
                })
                .collect::<Vec<_>>()
        };
        for (agent_id, agent_root, body) in &notes {
            for (uri, path) in placed(agent_root) {
                crate::auth::write_principal_root_object(
                    &data_dir, agent_id, agent_root, &uri, &path, body,
                )
                .unwrap();
            }
        }
        // Each agent's two files sit under its own root only: the other
        // agent's copy of the same path is the other agent's own file, and no
        // agent can read an object named outside its own root.
        for (mine, theirs) in [(0usize, 1usize), (1, 0)] {
            let (agent_id, agent_root, body) = &notes[mine];
            let (other_id, other_root, other_body) = &notes[theirs];
            assert_ne!(body, other_body, "the two agents' journals differ");
            for (uri, path) in placed(agent_root) {
                assert_eq!(
                    crate::auth::read_principal_root_object(
                        &data_dir, agent_id, agent_root, &uri, &path,
                    )
                    .unwrap(),
                    *body
                );
                let other_uri = uri.replacen(*agent_root, other_root.as_str(), 1);
                let other_path =
                    elastos_common::localhost::rooted_localhost_fs_path(&data_dir, &other_uri)
                        .unwrap();
                assert_eq!(
                    crate::auth::read_principal_root_object(
                        &data_dir,
                        other_id,
                        other_root,
                        &other_uri,
                        &other_path,
                    )
                    .unwrap(),
                    *other_body,
                    "{other_path:?} holds no more than {other_id}'s own file"
                );
                assert_eq!(
                    crate::auth::read_principal_root_object(
                        &data_dir, other_id, other_root, &uri, &path,
                    )
                    .unwrap_err()
                    .to_string(),
                    "principal-root object URI is outside the principal root",
                    "{other_id} reads {agent_id}'s object"
                );
            }
        }

        // The one-shot component has ended, so a stop finds nothing; a new
        // launch takes the same principal and the same root.
        assert!(!runtime.stop_capsule_by_id(&first.id).await.unwrap());
        let again = launch(&a).await.unwrap().0;
        assert_ne!(again.id, first.id);
        assert_eq!(root(&a), root_a);
        assert_eq!(invoked(&a).len(), 2, "the relaunch makes one more call");
        // Both agents read their own two files back after the relaunch.
        for (agent_id, agent_root, body) in &notes {
            for (uri, path) in placed(agent_root) {
                assert_eq!(
                    crate::auth::read_principal_root_object(
                        &data_dir, agent_id, agent_root, &uri, &path,
                    )
                    .unwrap(),
                    *body
                );
            }
        }
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
    /// as one, whatever the request names or the person owns.
    #[test]
    fn a_capsule_that_does_not_declare_an_agent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "not-an-agent");
        let error = admit_agent_launch(
            Some(dir.path()),
            &capsule_dir,
            Some("person:local:a5-owner"),
            "agent:v2:cccccccccccccccccccccccccccccccc",
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
        let error = admit_agent_launch(
            None,
            &capsule_dir,
            Some("person:local:a5-owner"),
            "agent:v2:cccccccccccccccccccccccccccccccc",
        )
        .unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "an agent launch needs this Home's data directory");
    }
}
