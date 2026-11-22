//! System Start, through the gateway route and the Home Runtime's launch route.
//!
//! The admin's System token is a Home-hosted projection: its authority is
//! Home, and its selected resource and executable are both System. The
//! existing step-up ceremony accepts that shape and refuses a direct System
//! token. Start then presents the same token, so the step-up is bound to the
//! launch that authorizes the route.

use super::*;
use crate::agent_admission::tests::{installed_agent_host, Signed};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use elastos_identity::{IdentityStore, StoredCredential};
use p256::ecdsa::signature::Signer;
use sha2::Digest;
use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

const BEGIN: &str = "/api/auth/passkey-step-up/begin";
const COMPLETE: &str = "/api/auth/passkey-step-up/complete";
const ENABLE: &str = "/api/apps/system/agents/enable";
const CREATE: &str = "/api/apps/system/agents/create";
const ACTIVATE: &str = "/api/apps/system/agents/activate";
const LAUNCH: &str = "/api/apps/system/agents/launch";
const STOP: &str = "/api/apps/system/agents/stop";
const HOST: &str = "agent-host";
const ORIGIN: &str = "http://localhost:61180";

struct Person {
    home_token: String,
    system_token: String,
    principal_id: String,
    proof_binding_id: String,
    session_id: String,
    key: p256::ecdsa::SigningKey,
    credential_id: String,
    sign_count: Cell<u32>,
}

struct RuntimeHost {
    task: tokio::task::JoinHandle<()>,
    seen: Arc<std::sync::Mutex<Vec<Value>>>,
    stops: Arc<std::sync::Mutex<Vec<Value>>>,
    runtime: Arc<crate::runtime::Runtime>,
    audit: Arc<elastos_runtime::primitives::audit::AuditLog>,
}

impl Drop for RuntimeHost {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct World {
    home: crate::installed_release::tests::Fixture,
    _scratch: tempfile::TempDir,
    app: Router,
    admin: Person,
    other: Person,
    guest: Person,
    runtime: RuntimeHost,
    agent_a: String,
    agent_b: String,
}

fn install_probe(data: &std::path::Path) {
    use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
    let dir = data.join("capsules").join(HOST);
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/components/a5-launch-probe");
    let wasm = std::fs::read(fixture.join("a5-launch-probe.component.wasm")).unwrap();
    let mut manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&std::fs::read(fixture.join("capsule.json")).unwrap()).unwrap();
    manifest.name = HOST.to_string();
    manifest.signature = None;
    sign_capsule(
        &SigningKey::from_bytes(&[71; 32]),
        &mut manifest,
        &hash_content(&wasm),
    )
    .unwrap();
    std::fs::write(
        dir.join("capsule.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("a5-launch-probe.component.wasm"), wasm).unwrap();
}

fn cose_key(seed: u8) -> (p256::ecdsa::SigningKey, String) {
    let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let mut cose = Vec::with_capacity(77);
    cose.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
    cose.extend_from_slice(point.x().unwrap());
    cose.extend_from_slice(&[0x22, 0x58, 0x20]);
    cose.extend_from_slice(point.y().unwrap());
    (key, URL_SAFE_NO_PAD.encode(cose))
}

fn add_person(
    data: &std::path::Path,
    store: &mut IdentityStore,
    seed: u8,
    name: &str,
    role: crate::auth::RuntimePrincipalRole,
) -> Person {
    let (key, public_key) = cose_key(seed);
    let credential_id = URL_SAFE_NO_PAD.encode(format!("agent-start-{seed}"));
    store.add_credential(StoredCredential {
        credential_id: credential_id.clone(),
        public_key: public_key.clone(),
        sign_count: 0,
        rp_id: "localhost".to_string(),
    });
    let now = crate::auth::now_ts();
    let binding = ProofBinding::passkey_webauthn(PasskeyWebAuthnBinding {
        credential_id: credential_id.clone(),
        public_key,
        sign_count: 0,
        user_verified: true,
        origin: ORIGIN.to_string(),
        rp_id: "localhost".to_string(),
        created_at: now,
        last_used_at: now,
        revoked_at: None,
    });
    let principal_id =
        crate::auth::passkey_credential_principal_id("localhost", &credential_id).unwrap();
    let principal = crate::auth::upsert_principal_for_binding_as_role_named(
        data,
        binding,
        principal_id,
        role,
        Some(name),
        now,
    )
    .unwrap();
    crate::auth::store_test_principal_root_protection(data, &principal.principal_id);
    let grant = AuthSessionGrantV1 {
        schema: AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", uuid_like_token()),
        session_id: format!("auth:{}", uuid_like_token()),
        principal_id: principal.principal_id.clone(),
        proof_binding_id: principal.proof_binding_id.clone(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        apps: vec![
            HOME_CAPSULE_ID.to_string(),
            PEOPLE_CAPSULE_ID.to_string(),
            SYSTEM_CAPSULE_ID.to_string(),
        ],
    };
    crate::auth::store_session_grant(data, grant.clone()).unwrap();
    let context = HomeLaunchTokenContext::for_test(
        grant.principal_id.clone(),
        grant.session_id.clone(),
        Some(grant.proof_binding_id.clone()),
        grant.grant_id.clone(),
        crate::auth::PrincipalKind::Human,
    );
    Person {
        home_token: issue_home_launch_token_for_auth_grant(data, HOME_CAPSULE_ID, &grant).unwrap(),
        system_token: issue_home_projection_launch_token_with_context(
            data,
            SYSTEM_CAPSULE_ID,
            SYSTEM_CAPSULE_ID,
            &context,
        )
        .unwrap(),
        principal_id: principal.principal_id,
        proof_binding_id: principal.proof_binding_id,
        session_id: grant.session_id,
        key,
        credential_id,
        sign_count: Cell::new(1),
    }
}

fn assertion(person: &Person, challenge: &str) -> Value {
    let count = person.sign_count.get();
    person.sign_count.set(count + 1);
    let client = serde_json::json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": ORIGIN,
    })
    .to_string();
    let mut auth = Sha256::digest(b"localhost").to_vec();
    auth.push(0x05);
    auth.extend_from_slice(&count.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(client.as_bytes()));
    let signature: p256::ecdsa::Signature = person.key.sign(&signed);
    json!({
        "id": person.credential_id,
        "rawId": person.credential_id,
        "type": "public-key",
        "response": {
            "clientDataJson": URL_SAFE_NO_PAD.encode(client.as_bytes()),
            "authenticatorData": URL_SAFE_NO_PAD.encode(auth),
            "signature": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
            "userHandle": null,
        }
    })
}

async fn call(
    app: &Router,
    path: &str,
    token: &str,
    origin: &'static str,
    body: Option<Value>,
) -> (StatusCode, String) {
    let request = test_browser_request("localhost:61180", origin)
        .method("POST")
        .uri(path)
        .header("x-elastos-home-token", token)
        .header(CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn step_up(app: &Router, person: &Person, agent_id: &str) -> String {
    let (status, body) = call(
        app,
        BEGIN,
        &person.home_token,
        ORIGIN,
        Some(json!({
            "schema": "elastos.auth.passkey-step-up.begin.request/v1",
            "app_token": person.system_token,
            "operation": "agent.start",
            "request": { "agent_id": agent_id },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "step-up begin: {body}");
    let begun: Value = serde_json::from_str(&body).unwrap();
    let ceremony = begun["ceremony_id"].as_str().unwrap();
    let challenge = begun["options"]["publicKey"]["challenge"].as_str().unwrap();
    let (status, body) = call(
        app,
        COMPLETE,
        &person.home_token,
        ORIGIN,
        Some(json!({
            "schema": "elastos.auth.passkey-step-up.complete.request/v1",
            "ceremony_id": ceremony,
            "response": assertion(person, challenge),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "step-up complete: {body}");
    serde_json::from_str::<Value>(&body).unwrap()["step_up_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn start(
    world: &World,
    person: &Person,
    agent_id: &str,
    step_up_token: &str,
) -> (StatusCode, String) {
    call(
        &world.app,
        LAUNCH,
        &person.system_token,
        "null",
        Some(json!({
            "agent_id": agent_id,
            "step_up_token": step_up_token,
        })),
    )
    .await
}

async fn stop(world: &World, person: &Person, agent_id: &str) -> (StatusCode, String) {
    call(
        &world.app,
        STOP,
        &person.system_token,
        "null",
        Some(json!({ "agent_id": agent_id })),
    )
    .await
}

async fn live(world: &World) -> Vec<crate::runtime::RunningCapsuleInfo> {
    world
        .runtime
        .runtime
        .list_capsules()
        .await
        .into_iter()
        .filter(|info| info.ended_at.is_none())
        .collect()
}

fn live_principal(rows: &[crate::runtime::RunningCapsuleInfo], principal: &str) -> usize {
    rows.iter()
        .filter(|info| info.principal.as_deref() == Some(principal))
        .count()
}

/// `(agent_id, owner, host cid, launch id, session)` from launch and stop audits.
fn audit_tuples(world: &World, kind: &str) -> Vec<(String, String, String, String, String)> {
    use elastos_runtime::primitives::audit::AuditEvent;
    world
        .runtime
        .audit
        .recent_events(usize::MAX)
        .into_iter()
        .filter_map(|event| match (kind, event) {
            (
                "launch",
                AuditEvent::CapsuleLaunch {
                    agent_id: Some(agent_id),
                    owner: Some(owner),
                    cid: Some(cid),
                    launch_id: Some(launch_id),
                    session_id: Some(session_id),
                    ..
                },
            )
            | (
                "stop",
                AuditEvent::CapsuleStop {
                    agent_id: Some(agent_id),
                    owner: Some(owner),
                    cid: Some(cid),
                    launch_id: Some(launch_id),
                    session_id: Some(session_id),
                    ..
                },
            ) => Some((agent_id, owner, cid, launch_id, session_id)),
            _ => None,
        })
        .collect()
}

fn plain_host_row(principal: &str) -> crate::runtime::RunningCapsuleInfo {
    crate::runtime::RunningCapsuleInfo {
        id: "plain-host-session".to_string(),
        name: HOST.to_string(),
        status: "running".to_string(),
        capsule_type: elastos_common::CapsuleType::Wasm,
        handle: None,
        session_id: "plain-host-session".to_string(),
        principal: Some(principal.to_string()),
        cause: None,
        ended_at: None,
    }
}

fn grant_payload(token: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD.decode(token).unwrap();
    let envelope: Value = serde_json::from_slice(&bytes).unwrap();
    envelope["payload"].clone()
}

async fn guests(world: &World) -> usize {
    world.runtime.runtime.list_capsules().await.len()
}

fn mints(world: &World) -> u64 {
    agent_launch_grants_minted_for_test(&world.home.data)
}

struct RecordedRuntimePosts {
    launches: Arc<std::sync::Mutex<Vec<Value>>>,
    stops: Arc<std::sync::Mutex<Vec<Value>>>,
}

async fn record_capsule_post(
    axum::extract::State(seen): axum::extract::State<Arc<RecordedRuntimePosts>>,
    request: axum::http::Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();
    let record = request.method() == axum::http::Method::POST
        && (path == "/api/capsules" || path == "/api/capsules/stop-agent");
    if !record {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
        let slot = if path == "/api/capsules/stop-agent" {
            &seen.stops
        } else {
            &seen.launches
        };
        slot.lock().expect("recorded runtime posts").push(value);
    }
    next.run(axum::http::Request::from_parts(parts, Body::from(bytes)))
        .await
}

async fn serve_runtime(data: &std::path::Path) -> RuntimeHost {
    use elastos_runtime::capability::{CapabilityManager, CapabilityStore, PendingRequestStore};
    use elastos_runtime::primitives::audit::AuditLog;
    use elastos_runtime::primitives::metrics::MetricsManager;
    use elastos_runtime::session::SessionRegistry;

    let storage = Arc::new(
        elastos_storage::providers::LocalFSProvider::new(data.join("agent-start-storage"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(crate::runtime::Runtime::with_providers_and_component(
        storage,
        Vec::new(),
        Some(Arc::new(
            elastos_compute::providers::ComponentProvider::new(),
        )),
    ));
    runtime
        .configure_capsule_admission(data, &[], false)
        .await
        .unwrap();
    let audit = Arc::new(AuditLog::new());
    let kept_audit = audit.clone();
    let sessions = Arc::new(SessionRegistry::new(audit.clone()));
    let store = Arc::new(CapabilityStore::new());
    let manager = Arc::new(CapabilityManager::new(
        store.clone(),
        audit.clone(),
        Arc::new(MetricsManager::new()),
    ));
    let pending = Arc::new(PendingRequestStore::new(audit.clone()));
    // The probe's first bridge call waits on a capability request. Without
    // this, the guest ends before an owner's Stop can see a live row.
    runtime
        .set_provider_registry(
            Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
            manager.clone(),
            pending.clone(),
            data.to_path_buf(),
        )
        .await;
    let secret = "agent-start-attach".to_string();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let stops = Arc::new(std::sync::Mutex::new(Vec::new()));
    let router = crate::api::server::build_router(crate::api::server::ServerConfig {
        runtime: runtime.clone(),
        session_registry: sessions,
        capability_manager: manager,
        capability_store: store,
        pending_store: pending,
        namespace_store: None,
        provider_registry: None,
        audit_log: Some(audit),
        identity_state: None,
        docs_dir: None,
        addr: "127.0.0.1:0".to_string(),
        capsule_dir: None,
        data_dir: Some(data.to_path_buf()),
        tls_config: None,
        supervisor: None,
        ready_tx: None,
        attach_secret: Some(secret.clone()),
        host_helpers: Vec::new(),
    })
    .unwrap()
    .layer(axum::middleware::from_fn_with_state(
        Arc::new(RecordedRuntimePosts {
            launches: seen.clone(),
            stops: stops.clone(),
        }),
        record_capsule_post,
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let url = format!("http://{addr}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let mut healthy = false;
    for _ in 0..50 {
        if client
            .get(format!("{url}/api/health"))
            .send()
            .await
            .ok()
            .is_some_and(|response| response.status().is_success())
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(healthy, "the runtime launch route did not answer health");
    std::fs::write(
        crate::runtime_control::home_runtime_coord_path(data),
        serde_json::to_vec(&json!({
            "api_url": url,
            "attach_secret": secret,
            "pid": std::process::id(),
            "runtime_kind": crate::runtime_control::RUNTIME_KIND_MANAGED_HOME,
        }))
        .unwrap(),
    )
    .unwrap();
    RuntimeHost {
        task,
        seen,
        stops,
        runtime,
        audit: kept_audit,
    }
}

async fn world() -> World {
    let home = installed_agent_host(Signed::ByPublisher);
    install_probe(&home.data);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&home.data, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut store = IdentityStore::new(&home.data).unwrap();
    store.load().unwrap();
    let admin = add_person(
        &home.data,
        &mut store,
        7,
        "Start admin",
        crate::auth::RuntimePrincipalRole::Admin,
    );
    let other = add_person(
        &home.data,
        &mut store,
        8,
        "Other owner",
        crate::auth::RuntimePrincipalRole::Admin,
    );
    let guest = add_person(
        &home.data,
        &mut store,
        9,
        "Guest owner",
        crate::auth::RuntimePrincipalRole::Guest,
    );
    store.save().unwrap();
    let runtime = serve_runtime(&home.data).await;
    let scratch = tempfile::tempdir().unwrap();
    let state = GatewayState {
        cache_dir: home.data.clone(),
        data_dir: home.data.clone(),
        ..test_state(scratch.path())
    };
    let app = gateway_router(state);
    let (status, body) = call(&app, ENABLE, &admin.system_token, "null", None).await;
    assert_eq!(status, StatusCode::OK, "enable: {body}");
    let created = |name: &str, request_id: &str| {
        json!({
            "display_name": name,
            "agent_host": HOST,
            "request_id": request_id,
        })
    };
    let (status, body) = call(
        &app,
        CREATE,
        &admin.system_token,
        "null",
        Some(created("Helper A", "request-a")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create A: {body}");
    let agent_a = serde_json::from_str::<Value>(&body).unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, body) = call(
        &app,
        CREATE,
        &admin.system_token,
        "null",
        Some(created("Helper B", "request-b")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create B: {body}");
    let agent_b = serde_json::from_str::<Value>(&body).unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();
    for agent_id in [&agent_a, &agent_b] {
        let (status, body) = call(
            &app,
            ACTIVATE,
            &admin.system_token,
            "null",
            Some(json!({ "agent_id": agent_id, "active": true })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "activate {agent_id}: {body}");
    }
    World {
        home,
        _scratch: scratch,
        app,
        admin,
        other,
        guest,
        runtime,
        agent_a,
        agent_b,
    }
}

#[tokio::test]
async fn system_agent_launch_without_a_fresh_step_up_starts_zero_guests() {
    let world = world().await;
    let (status, body) = start(&world, &world.admin, &world.agent_a, "").await;
    assert_eq!(
        guests(&world).await,
        0,
        "a start without a fresh step-up started a guest: {status} {body}"
    );
    assert_eq!(
        mints(&world),
        0,
        "a start without a fresh step-up minted a grant: {status} {body}"
    );
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn system_agent_launch_step_up_for_one_agent_does_not_start_another() {
    let world = world().await;
    let token = step_up(&world.app, &world.admin, &world.agent_a).await;
    let (status, body) = start(&world, &world.admin, &world.agent_b, &token).await;
    assert_eq!(
        guests(&world).await,
        0,
        "a step-up for one agent started another: {status} {body}"
    );
    assert_eq!(
        mints(&world),
        0,
        "a step-up for one agent minted a grant for another: {status} {body}"
    );
    assert_ne!(status, StatusCode::OK, "{body}");
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the unused token could not start its own agent: {body}"
    );
    assert_eq!(guests(&world).await, 1);
}

#[tokio::test]
async fn system_agent_launch_replayed_step_up_fails() {
    let world = world().await;
    let token = step_up(&world.app, &world.admin, &world.agent_a).await;
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    assert_eq!(status, StatusCode::OK, "first start: {body}");
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a replayed step-up started a guest: {body}"
    );
    assert_eq!(
        guests(&world).await,
        1,
        "a replayed step-up started another guest"
    );
    assert_eq!(mints(&world), 1, "a replayed step-up minted another grant");
}

#[tokio::test]
async fn system_agent_launch_with_a_fresh_step_up_starts_one_short_agent_bound_guest() {
    let world = world().await;
    let token = step_up(&world.app, &world.admin, &world.agent_a).await;
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    let recorded = world
        .runtime
        .seen
        .lock()
        .expect("recorded launches")
        .clone();
    assert_eq!(
        recorded.len(),
        1,
        "a fresh start did not send one grant: {status} {body}"
    );
    let payload = grant_payload(recorded[0]["launch_grant"].as_str().unwrap());
    let resource = format!("elastos://agent/{}", world.agent_a);
    assert_eq!(
        payload["launch_context"]["selected_resource"].as_str(),
        Some(resource.as_str()),
        "the grant is not bound to this agent"
    );
    let iat = payload["iat"].as_u64().unwrap();
    let exp = payload["exp"].as_u64().unwrap();
    assert!(
        exp > iat && exp - iat <= 60,
        "the grant is not short: iat={iat} exp={exp}"
    );
    assert_eq!(
        payload["launch_context"]["executable_actor"].as_str(),
        Some(HOST)
    );
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(mints(&world), 1);
    assert_eq!(
        guests(&world).await,
        1,
        "a fresh step-up did not start one guest"
    );
    let answer: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(answer["agent_id"].as_str(), Some(world.agent_a.as_str()));
    assert_eq!(answer["status"], "starting");
    assert_eq!(answer["session_id"], answer["capsule_id"]);
    let grant = recorded[0]["launch_grant"].as_str().unwrap();
    assert!(
        !body.contains(grant),
        "the start response carried the internal grant"
    );
    let running = world.runtime.runtime.list_capsules().await;
    assert_eq!(running[0].name, HOST);
    assert_eq!(
        running[0].principal.as_deref(),
        Some(world.agent_a.as_str())
    );
}

#[tokio::test]
async fn system_agent_launch_refuses_a_guest() {
    let world = world().await;
    let now = crate::auth::now_ts();
    let caller = crate::agents::Caller {
        principal_id: &world.guest.principal_id,
        proof_binding_id: &world.guest.proof_binding_id,
        session_id: &world.guest.session_id,
    };
    let created = crate::agents::create(
        &world.home.data,
        &caller,
        &crate::agents::CreateRequest {
            display_name: "Guest helper".to_string(),
            agent_host: HOST.to_string(),
            request_id: "request-guest".to_string(),
        },
        |host| crate::agent_admission::verify_agent_host(&world.home.data, host),
        now,
    )
    .unwrap();
    crate::agents::set_active(&world.home.data, &caller, &created.agent_id, true, now).unwrap();
    let token = step_up(&world.app, &world.guest, &created.agent_id).await;
    let (status, body) = start(&world, &world.guest, &created.agent_id, &token).await;
    assert_eq!(
        guests(&world).await,
        0,
        "a guest started an agent: {status} {body}"
    );
    assert_eq!(mints(&world), 0, "a guest minted a grant: {status} {body}");
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("admin passkey required"), "{body}");
}

#[tokio::test]
async fn system_agent_launch_expired_step_up_starts_zero_guests() {
    let world = world().await;
    let token = step_up(&world.app, &world.admin, &world.agent_a).await;
    // 121 seconds is past Start's 120 second window and inside the token's
    // own 180 second lifetime, so this refuses because of the Start cap.
    advance_passkey_step_up_clock_for_test(&world.home.data, 121);
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    assert_eq!(
        guests(&world).await,
        0,
        "an expired step-up started a guest: {status} {body}"
    );
    assert_eq!(
        mints(&world),
        0,
        "an expired step-up minted a grant: {status} {body}"
    );
    assert_ne!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn system_agent_launch_other_owner_step_up_starts_zero_guests() {
    let world = world().await;
    let token = step_up(&world.app, &world.other, &world.agent_a).await;
    let (status, body) = start(&world, &world.admin, &world.agent_a, &token).await;
    assert_eq!(
        guests(&world).await,
        0,
        "another owner's step-up started an agent: {status} {body}"
    );
    assert_eq!(
        mints(&world),
        0,
        "another owner's step-up minted a grant: {status} {body}"
    );
    assert_ne!(status, StatusCode::OK, "{body}");
}

async fn started(world: &World, agent_id: &str) -> Value {
    let token = step_up(&world.app, &world.admin, agent_id).await;
    let (status, body) = start(world, &world.admin, agent_id, &token).await;
    assert_eq!(status, StatusCode::OK, "start {agent_id}: {body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn owner_stop_stops_that_agents_row_and_writes_the_audit() {
    let world = world().await;
    let started = started(&world, &world.agent_a).await;
    let session = started["session_id"].as_str().unwrap().to_string();
    let (status, body) = stop(&world, &world.admin, &world.agent_a).await;
    assert_eq!(status, StatusCode::OK, "owner stop: {body}");
    let rows = live(&world).await;
    assert_eq!(
        live_principal(&rows, &world.agent_a),
        0,
        "the owner's stop left this agent's row running: {body}"
    );
    let launches = audit_tuples(&world, "launch");
    let stops = audit_tuples(&world, "stop");
    assert_eq!(
        stops, launches,
        "the stop audit does not record the start tuple"
    );
    assert_eq!(stops.len(), 1, "one stop record: {stops:?}");
    assert_eq!(stops[0].0, world.agent_a);
    assert_eq!(stops[0].1, world.admin.principal_id);
    assert!(!stops[0].2.is_empty(), "the host CID is empty");
    assert!(
        stops[0].3.starts_with("launch:"),
        "launch id {}",
        stops[0].3
    );
    assert_eq!(stops[0].4, session);
    let posted = world.runtime.stops.lock().expect("recorded stops").clone();
    assert_eq!(
        posted.len(),
        1,
        "the hop did not ask the Runtime once: {posted:?}"
    );
    assert_eq!(
        posted[0].as_object().map(|body| body.len()),
        Some(1),
        "the hop sent more than the agent id: {posted:?}"
    );
    assert_eq!(posted[0]["agent_id"], world.agent_a);
}

#[tokio::test]
async fn stop_of_agent_a_leaves_agent_b_running() {
    let world = world().await;
    started(&world, &world.agent_a).await;
    started(&world, &world.agent_b).await;
    let (status, body) = stop(&world, &world.admin, &world.agent_a).await;
    let rows = live(&world).await;
    assert!(
        status == StatusCode::OK
            && live_principal(&rows, &world.agent_a) == 0
            && live_principal(&rows, &world.agent_b) == 1,
        "stopping A stopped B: {status} {body} rows={rows:?}"
    );
}

#[tokio::test]
async fn stop_by_another_owner_or_a_guest_is_refused() {
    let world = world().await;
    started(&world, &world.agent_a).await;
    let (other_status, other_body) = stop(&world, &world.other, &world.agent_a).await;
    let (guest_status, guest_body) = stop(&world, &world.guest, &world.agent_a).await;
    let rows = live(&world).await;
    assert!(
        other_status != StatusCode::OK
            && guest_status != StatusCode::OK
            && live_principal(&rows, &world.agent_a) == 1,
        "other={other_status} {other_body} guest={guest_status} {guest_body} rows={rows:?}"
    );
}

#[tokio::test]
async fn stop_of_a_non_agent_capsule_with_the_hosts_name_is_refused() {
    let world = world().await;
    started(&world, &world.agent_a).await;
    world
        .runtime
        .runtime
        .register_capsule(plain_host_row(&world.admin.principal_id))
        .await;
    let (host_status, host_body) = stop(&world, &world.admin, HOST).await;
    let (status, body) = stop(&world, &world.admin, &world.agent_a).await;
    let rows = live(&world).await;
    assert!(
        host_status != StatusCode::OK
            && status == StatusCode::OK
            && live_principal(&rows, &world.agent_a) == 0
            && live_principal(&rows, &world.admin.principal_id) == 1
            && rows.iter().any(|row| row.name == HOST),
        "stopping the agent stopped the non-agent capsule with the host's name: host={host_status} {host_body} agent={status} {body} rows={rows:?}"
    );
}

#[tokio::test]
async fn two_starts_with_one_step_up_start_one_guest() {
    let world = world().await;
    let token = step_up(&world.app, &world.admin, &world.agent_a).await;
    let first = start(&world, &world.admin, &world.agent_a, &token);
    let second = start(&world, &world.admin, &world.agent_a, &token);
    let ((left_status, left_body), (right_status, right_body)) = tokio::join!(first, second);
    let oks = [left_status, right_status]
        .into_iter()
        .filter(|status| *status == StatusCode::OK)
        .count();
    assert_eq!(
        oks, 1,
        "two starts shared one step-up: {left_status} {left_body} / {right_status} {right_body}"
    );
    let rows = live(&world).await;
    assert_eq!(
        live_principal(&rows, &world.agent_a),
        1,
        "two starts shared one step-up and both guests are running"
    );
    assert_eq!(
        mints(&world),
        1,
        "two starts shared one step-up and both minted"
    );
}
