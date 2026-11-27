//! The agent Runtime hosted in the gateway process.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::sync::oneshot;

use super::super::gateway_home_token::HomeLaunchTokenContext;
use super::HOME_CAPSULE_ID;

const HOST: &str = "a5-launch-probe";
const REGISTRY_CID: &str = "bafkreia5probe";

const COMPONENT: &str = r#"(component
  (import "elastos:bus/types@1.0.0" (instance $types
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "internal" string)))
    (export "bus-error" (type (eq $error)))))
  (alias export $types "bus-error" (type $bus-error))
  (core module $m
    (memory (export "memory") 1)
    /*BODY*/
    (func (export "run") (result i32) (call $body) (i32.const 0)))
  (core instance $i (instantiate $m))
  (func $run (result (result (error $bus-error)))
    (canon lift (core func $i "run") (memory $i "memory")))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#;

const FUEL_BODY: &str = r#"(func $body (local $x f64)
  (local.set $x (f64.const 1.0000001))
  (loop $again
    (local.set $x (f64.div (local.get $x) (f64.const 1.0000001)))
    (local.set $x (f64.mul (local.get $x) (f64.const 1.0000001)))
    (br $again)))"#;

const TRAP_BODY: &str = "(func $body unreachable)";

const MEMORY_BODY: &str = r#"(func $body
  (loop $again
    (drop (memory.grow (i32.const 1)))
    (br $again)))"#;

struct Home {
    _temp: tempfile::TempDir,
    _lock: crate::host_lock::FileLock,
    data: PathBuf,
    owner: String,
    proof: String,
    session: String,
    context: HomeLaunchTokenContext,
}

impl Home {
    fn open() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[0x44; 32]);
        let trusted = hex::encode(key.verifying_key().to_bytes());
        std::fs::write(
            data.join("config.toml"),
            format!("dev_mode = false\ntrusted_keys = [\"{trusted}\"]\n"),
        )
        .unwrap();
        let context = super::super::gateway_home_token::bind_device_session_grant(
            &data,
            &[HOME_CAPSULE_ID, HOST],
        )
        .unwrap();
        let owner = context.principal_id().to_string();
        crate::auth::store_test_principal_root_protection(&data, &owner);
        crate::api::routes::tests::make_admin(&data, &owner);
        let record = crate::auth::stored_principal_record(&data, &owner)
            .unwrap()
            .unwrap();
        let session = context.session_id().to_string();
        let proof = record.proof_binding_id.clone();
        let home = Self {
            _temp: temp,
            _lock: crate::host_lock::acquire_host_process_lock(&data, "gateway", "127.0.0.1:0")
                .unwrap(),
            data,
            owner,
            proof,
            session,
            context,
        };
        home.enable();
        home
    }

    fn caller(&self) -> crate::agents::Caller<'_> {
        crate::agents::Caller {
            principal_id: &self.owner,
            proof_binding_id: &self.proof,
            session_id: &self.session,
        }
    }

    fn enable(&self) {
        crate::agents::set_enabled(&self.data, &self.caller(), true, 1).unwrap();
    }

    fn create_agent(&self, name: &str, cid: &str) -> String {
        let id = crate::agents::create(
            &self.data,
            &self.caller(),
            &crate::agents::CreateRequest {
                display_name: name.to_string(),
                agent_host: HOST.to_string(),
                request_id: format!("request-{name}"),
            },
            |host| {
                Ok(
                    crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                        host,
                        REGISTRY_CID,
                        cid,
                    ),
                )
            },
            1,
        )
        .unwrap()
        .agent_id;
        crate::agents::set_active(&self.data, &self.caller(), &id, true, 1).unwrap();
        id
    }

    async fn launch(&self, agent_id: &str, dir: &Path) -> String {
        let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
            &self.data,
            agent_id,
            HOST,
            &self.context,
        )
        .unwrap();
        super::super::gateway_home_runtime::launch_runtime_agent(&self.data, dir, agent_id, &grant)
            .await
            .unwrap()
            .session_id
    }

    async fn plane(&self) -> Plane {
        // The product Home registers the plane here. `start` alone leaves
        // Off with nothing to stop.
        crate::api::agent_plane::ensure_running(&self.data, None)
            .await
            .unwrap();
        let coords = wait_coords(&self.data).await;
        Plane {
            url: coords.api_url.clone(),
            secret: coords.attach_secret.clone(),
            data: self.data.clone(),
        }
    }
}

struct Plane {
    url: String,
    secret: String,
    data: PathBuf,
}

impl Plane {
    fn runtime(&self) -> Arc<crate::runtime::Runtime> {
        crate::api::agent_plane::plane_runtime(&self.data).expect("the plane is registered")
    }

    async fn token(&self) -> String {
        shell_token(&self.url, &self.secret).await
    }

    async fn shutdown(self) {
        let url = self.url.clone();
        stop_plane(&self.data).await;
        port_closed(&url).await;
    }
}

struct Gateway {
    addr: String,
    agent_url: String,
    secret: String,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl Gateway {
    async fn start(data: &Path) -> Self {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");
        let (stop_tx, stop_rx) = oneshot::channel();
        let task_addr = addr.clone();
        let task_data = data.to_path_buf();
        std::fs::create_dir_all(task_data.join("cache")).unwrap();
        let task = tokio::spawn(async move {
            super::super::gateway_server::start_gateway_server_with_shutdown(
                &task_addr,
                Some(Arc::new(elastos_runtime::provider::ProviderRegistry::new())),
                super::super::gateway_server::GatewayCollaborationContext::default(),
                task_data.join("cache"),
                task_data,
                None,
                async move {
                    let _ = stop_rx.await;
                },
            )
            .await
        });
        let health_url = format!("http://{addr}/healthz");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut up = false;
        for _ in 0..200 {
            if task.is_finished() {
                panic!("gateway exited before health: {:?}", task.await);
            }
            if client
                .get(&health_url)
                .send()
                .await
                .ok()
                .is_some_and(|response| response.status().is_success())
            {
                up = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(up, "did not answer {health_url}");
        if crate::agents::home_enabled(data) {
            let coords = wait_coords(data).await;
            Self {
                addr,
                agent_url: coords.api_url,
                secret: coords.attach_secret,
                task,
                stop: Some(stop_tx),
            }
        } else {
            Self {
                addr,
                agent_url: String::new(),
                secret: String::new(),
                task,
                stop: Some(stop_tx),
            }
        }
    }

    async fn health(&self) {
        wait_http(&format!("http://{}/healthz", self.addr)).await;
        wait_http(&format!("{}/api/health", self.agent_url)).await;
    }

    async fn cause(&self, session: &str) -> String {
        for _ in 0..400 {
            self.health().await;
            if let Some(cause) = capsule_cause(&self.agent_url, &self.secret, session).await {
                return cause;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("guest did not end");
    }

    async fn shutdown(mut self) {
        let url = self.agent_url.clone();
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap().unwrap();
        port_closed(&url).await;
    }
}

async fn capsule_row(url: &str, secret: &str, session: &str) -> Option<Value> {
    let token = shell_token(url, secret).await;
    let body = reqwest::Client::new()
        .get(format!("{url}/api/capsules"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let value: Value = serde_json::from_str(&body).unwrap();
    value["capsules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["session_id"] == session)
        .cloned()
}

async fn capsule_cause(url: &str, secret: &str, session: &str) -> Option<String> {
    capsule_row(url, secret, session)
        .await
        .and_then(|row| row["cause"].as_str().map(str::to_string))
}

async fn stop_plane(data: &Path) {
    let (_, closed) = crate::api::agent_plane::stop_running(data).await;
    closed.expect("agent plans closed");
}

async fn capsule_live(url: &str, secret: &str, session: &str) -> bool {
    capsule_row(url, secret, session)
        .await
        .is_some_and(|row| row["cause"].is_null())
}

fn socket(url: &str) -> std::net::SocketAddr {
    url.trim_start_matches("http://").parse().unwrap()
}

async fn port_closed(url: &str) {
    let addr = socket(url);
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener stayed up at {url}");
}

async fn shell_token(url: &str, secret: &str) -> String {
    let value: Value = reqwest::Client::new()
        .post(format!("{url}/api/auth/attach"))
        .json(&json!({"secret": secret, "scope": "shell"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    value["token"].as_str().unwrap().to_string()
}

async fn wait_http(url: &str) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for _ in 0..200 {
        if client
            .get(url)
            .send()
            .await
            .ok()
            .is_some_and(|response| response.status().is_success())
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("did not answer {url}");
}

async fn refused_start(data: &Path) -> String {
    match crate::api::agent_plane::start(data, None).await {
        Err(error) => error.to_string(),
        Ok(_) => panic!("agent runtime started"),
    }
}

async fn wait_coords(data: &Path) -> crate::runtime_control::RuntimeCoords {
    for _ in 0..200 {
        if let Some(coords) = crate::api::agent_plane::live_coords(data).await {
            return coords;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("agent coordinates did not appear");
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/components/a5-launch-probe")
}

fn sign_bytes(dir: &Path, wasm: &[u8]) -> String {
    use elastos_runtime::signature::{hash_content, sign_capsule, SigningKey};
    let key = SigningKey::from_bytes(&[0x44; 32]);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(fixture().join("capsule.json"), dir.join("capsule.json")).unwrap();
    let mut manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap();
    manifest.entrypoint = "guest.component.wasm".to_string();
    sign_capsule(&key, &mut manifest, &hash_content(wasm)).unwrap();
    std::fs::write(
        dir.join("capsule.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("guest.component.wasm"), wasm).unwrap();
    crate::stage_cmd::bundle_cid(dir).unwrap()
}

fn sign_wat(dir: &Path, body: &str) -> String {
    let wasm = wat::parse_str(COMPONENT.replace("/*BODY*/", body)).unwrap();
    sign_bytes(dir, &wasm)
}

fn sign_probe(dir: &Path) -> String {
    let wasm = std::fs::read(fixture().join("a5-launch-probe.component.wasm")).unwrap();
    sign_bytes(dir, &wasm)
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

#[test]
fn managed_child_still_refuses_agents() {
    let parent = Path::new("/home/data");
    let child = parent.join("managed-runtimes/home");
    let error = crate::agent_admission::require_home_runtime(&child, parent).unwrap_err();
    assert!(
        error
            .to_string()
            .contains(crate::agent_admission::NOT_THE_HOME),
        "{error}"
    );
    crate::agent_admission::require_home_runtime(parent, parent).unwrap();
    let source = include_str!("../../agent_admission.rs");
    let body = source
        .split("fn require_home_runtime")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(body.contains("sign_in_store != data_dir"));
    assert!(body.contains("NOT_THE_HOME"));
}

struct EnteredModel {
    entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait::async_trait]
impl elastos_runtime::provider::Provider for EnteredModel {
    async fn handle(
        &self,
        _request: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, elastos_runtime::provider::ProviderError>
    {
        Err(elastos_runtime::provider::ProviderError::Provider(
            "the stub answers raw calls".into(),
        ))
    }

    fn schemes(&self) -> Vec<&'static str> {
        vec!["model"]
    }

    fn name(&self) -> &'static str {
        "stub-model"
    }

    async fn send_raw(
        &self,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, elastos_runtime::provider::ProviderError> {
        self.entered
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(json!({ "seen": request["op"].clone() }))
    }
}

/// The plane installs the registry Home handed it. A raw model call on that
/// same registry enters the stub. A guest still needs a grant this plane does
/// not mint.
#[tokio::test]
async fn the_agent_runtime_calls_the_shared_model_provider() {
    let home = Home::open();
    let registry = Arc::new(elastos_runtime::provider::ProviderRegistry::new());
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    registry
        .register_sub_provider(
            "model",
            Arc::new(EnteredModel {
                entered: entered.clone(),
            }),
        )
        .await
        .unwrap();
    let plane = crate::api::agent_plane::start(&home.data, Some(registry.clone()))
        .await
        .unwrap();
    let response = plane
        .runtime
        .served_model_answer(&json!({ "op": "ping" }))
        .await
        .expect("the runtime serves the model through its stored registry");
    assert_eq!(response["seen"], "ping");
    assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
    plane.shutdown().await;
}

#[test]
fn agent_coordinates_are_created_owner_only_and_not_followed() {
    let source = include_str!("../agent_plane.rs");
    let write = source
        .split_once("fn write_coords(")
        .expect("write")
        .1
        .split_once("\nasync fn read_live(")
        .expect("read")
        .0;
    assert!(write.contains(".create_new(true)"), "{write}");
    assert!(write.contains(".mode(0o600)"), "{write}");
    assert!(write.contains("libc::O_NOFOLLOW"), "{write}");
    assert!(write.contains("std::fs::rename"), "{write}");
    assert!(!write.contains("set_permissions"), "{write}");
    assert!(!write.contains("write_runtime_coords"), "{write}");
    let read = source
        .split_once("fn read_owner_only(")
        .expect("read")
        .1
        .split_once("\nasync fn health(")
        .expect("health")
        .0;
    assert!(read.contains("libc::O_NOFOLLOW"), "{read}");
    assert!(!read.contains("std::fs::read"), "{read}");
}

#[test]
fn the_agent_runtime_keeps_the_listener_it_bound() {
    let source = include_str!("../agent_plane.rs");
    assert!(
        !source.contains("drop(listener)"),
        "the agent runtime drops the socket it bound"
    );
    assert!(
        source.contains("listener: Some(listener)"),
        "the agent runtime does not hand its socket to the server"
    );
}

#[test]
fn agent_runtime_does_not_grant_by_policy_or_start_a_shell() {
    let source = include_str!("../agent_plane.rs");
    for absent in [
        "AutoGrantVerifier",
        "RulesVerifier",
        "policy.json",
        "shell_capsule",
        "ELASTOS_SHADOW_MODE",
        "ELASTOS_SHELL_MODE",
    ] {
        assert!(!source.contains(absent), "{absent} is in the agent runtime");
    }
    let retire = include_str!("../gateway_agents.rs");
    assert!(retire.contains("end_live_agent"));
}

#[tokio::test]
async fn agent_coordinates_stay_owner_only_and_do_not_follow_a_symlink() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let kept = data.join("kept");
    std::fs::write(&kept, b"kept").unwrap();
    for name in [
        "runtime-coords.json",
        "gateway-runtime-coords.json",
        "home-runtime-coords.json",
    ] {
        std::fs::write(data.join(name), name.as_bytes()).unwrap();
    }
    std::os::unix::fs::symlink(&kept, crate::api::agent_plane::coords_path(&data)).unwrap();
    let _lock =
        crate::host_lock::acquire_host_process_lock(&data, "gateway", "127.0.0.1:0").unwrap();
    let error = refused_start(&data).await;
    assert!(error.contains("symlink"), "{error}");
    assert_eq!(std::fs::read(&kept).unwrap(), b"kept");
    for name in [
        "runtime-coords.json",
        "gateway-runtime-coords.json",
        "home-runtime-coords.json",
    ] {
        assert_eq!(std::fs::read(data.join(name)).unwrap(), name.as_bytes());
    }
    let loose = data.join("loose.json");
    std::fs::write(&loose, b"{}").unwrap();
    assert!(crate::api::agent_plane::live_coords(&data).await.is_none());
    assert_eq!(std::fs::read(&loose).unwrap(), b"{}");
    let coords = crate::api::agent_plane::coords_path(&data);
    std::fs::remove_file(&coords).unwrap();
    std::fs::write(&coords, b"{}").unwrap();
    std::fs::set_permissions(&coords, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(mode(&coords), 0o644);
    assert!(crate::api::agent_plane::live_coords(&data).await.is_none());
    assert_eq!(std::fs::read(&coords).unwrap(), b"{}");
}

#[tokio::test]
async fn agent_runtime_is_loopback_owner_only_and_stops_with_the_gateway() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let error = refused_start(&data).await;
    assert!(error.contains("owner of this data folder"), "{error}");
    let runtime_coords = data.join("runtime-coords.json");
    let home_coords = data.join("home-runtime-coords.json");
    std::fs::write(&runtime_coords, b"runtime-sentinel").unwrap();
    std::fs::write(&home_coords, b"home-sentinel").unwrap();
    let _lock =
        crate::host_lock::acquire_host_process_lock(&data, "gateway", "127.0.0.1:0").unwrap();
    let key = elastos_runtime::signature::SigningKey::from_bytes(&[0x44; 32]);
    let trusted = hex::encode(key.verifying_key().to_bytes());
    std::fs::write(
        data.join("config.toml"),
        format!("dev_mode = false\ntrusted_keys = [\"{trusted}\"]\n"),
    )
    .unwrap();
    let context = super::super::gateway_home_token::bind_device_session_grant(
        &data,
        &[HOME_CAPSULE_ID, HOST],
    )
    .unwrap();
    let owner = context.principal_id().to_string();
    crate::auth::store_test_principal_root_protection(&data, &owner);
    crate::api::routes::tests::make_admin(&data, &owner);
    let record = crate::auth::stored_principal_record(&data, &owner)
        .unwrap()
        .unwrap();
    let session = context.session_id().to_string();
    let caller = crate::agents::Caller {
        principal_id: &owner,
        proof_binding_id: &record.proof_binding_id,
        session_id: &session,
    };
    let mut gateway = Gateway::start(&data).await;
    assert!(
        crate::api::agent_plane::live_coords(&data).await.is_none(),
        "the agent runtime started before Allow"
    );
    crate::agents::set_enabled(&data, &caller, true, 1).unwrap();
    crate::api::agent_plane::ensure_running(&data, None)
        .await
        .unwrap();
    let coords = wait_coords(&data).await;
    gateway.agent_url = coords.api_url.clone();
    gateway.secret = coords.attach_secret.clone();
    assert!(
        coords.api_url.starts_with("http://127.0.0.1:"),
        "{}",
        coords.api_url
    );
    assert_eq!(coords.pid, std::process::id());
    assert_eq!(coords.runtime_kind, "agent");
    let agent_path = crate::api::agent_plane::coords_path(&data);
    assert_eq!(mode(&agent_path), 0o600);
    assert_eq!(std::fs::read(&runtime_coords).unwrap(), b"runtime-sentinel");
    assert_eq!(std::fs::read(&home_coords).unwrap(), b"home-sentinel");
    let gateway_bytes = std::fs::read(data.join("gateway-runtime-coords.json")).unwrap();
    assert_ne!(gateway_bytes, std::fs::read(&agent_path).unwrap());
    assert!(!gateway_bytes.is_empty());
    gateway.health().await;
    crate::agents::set_enabled(&data, &caller, false, 2).unwrap();
    stop_plane(&data).await;
    assert!(
        crate::api::agent_plane::live_coords(&data).await.is_none(),
        "the agent runtime stayed up after Off"
    );
    gateway.shutdown().await;
    assert!(!agent_path.exists());
    assert_eq!(std::fs::read(&runtime_coords).unwrap(), b"runtime-sentinel");
    assert_eq!(std::fs::read(&home_coords).unwrap(), b"home-sentinel");
}

#[tokio::test]
async fn agent_runtime_refuses_every_non_agent_start() {
    let home = Home::open();
    let host = home._temp.path().join("host");
    let cid = sign_wat(&host, TRAP_BODY);
    let _agent = home.create_agent("Refused", &cid);
    let plane = home.plane().await;
    let token = plane.token().await;
    let client = reqwest::Client::new();
    let post = |path: &str, body: Value| {
        let client = client.clone();
        let url = format!("{}{path}", plane.url);
        let token = token.clone();
        async move {
            let response = client
                .post(url)
                .header("authorization", format!("Bearer {token}"))
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            let text = response.text().await.unwrap();
            (status, text)
        }
    };
    let (status, text) = post("/api/capsules", json!({"path": host.display().to_string()})).await;
    assert_eq!(status.as_u16(), 400, "{text}");
    assert!(
        text.contains("this runtime launches a stored agent"),
        "{text}"
    );
    let (status, text) = post(
        "/api/capsules",
        json!({"path": host.display().to_string(), "agent_id": "agent:missing"}),
    )
    .await;
    assert_eq!(status.as_u16(), 400, "{text}");
    assert!(text.contains("launch grant"), "{text}");
    for path in [
        "/api/launch/open",
        "/api/supervisor/launch-capsule",
        "/api/supervisor/start-gateway",
        "/api/supervisor/ensure-capsule",
        "/api/supervisor/ensure-external",
        "/api/orchestrator/session",
        "/api/capability/request",
        "/api/capability/requests",
        "/api/capability/revoke-all",
        "/api/audit",
        "/api/test/create-session",
    ] {
        let (status, text) = post(path, json!({})).await;
        assert_eq!(status.as_u16(), 404, "{path} {status} {text}");
    }
    let (status, text) = post(
        "/api/capability/grant",
        json!({"request_id": "missing-ask"}),
    )
    .await;
    assert_eq!(status.as_u16(), 404, "{text}");
    assert!(text.contains("Request not found"), "{text}");
    let (status, text) = post("/api/capability/deny", json!({"request_id": "missing-ask"})).await;
    assert_ne!(status.as_u16(), 404, "{text}");
    assert!(text.contains("Request not found"), "{text}");
    let pending = client
        .get(format!("{}/api/capability/pending", plane.url))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(pending.status().as_u16(), 200);
    let pending_text = pending.text().await.unwrap();
    assert!(pending_text.contains("\"requests\""), "{pending_text}");
    let app_token: Value = client
        .post(format!("{}/api/auth/attach", plane.url))
        .json(&json!({"secret": plane.secret, "scope": "client"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let app_token = app_token["token"].as_str().unwrap();
    let refused = client
        .get(format!("{}/api/capability/pending", plane.url))
        .header("authorization", format!("Bearer {app_token}"))
        .send()
        .await
        .unwrap();
    let refused_status = refused.status();
    let refused_text = refused.text().await.unwrap();
    assert_eq!(refused_status.as_u16(), 403, "{refused_text}");
    assert!(refused_text.contains("Home app session"), "{refused_text}");
    let anonymous = client
        .get(format!("{}/api/capability/pending", plane.url))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status().as_u16(), 401);
    let listed = client
        .get(format!("{}/api/capsules", plane.url))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        listed.contains("\"capsules\":[]") || listed.contains("\"capsules\": []"),
        "{listed}"
    );
    plane.shutdown().await;
}

#[tokio::test]
async fn a_restart_shows_no_orphan_ask() {
    let home = Home::open();
    let plane = home.plane().await;
    let (store, _, _) = plane
        .runtime()
        .instance_authority_plane()
        .expect("the plane set its instance authority");
    let request = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string("capsule:restart-ask"),
            elastos_runtime::capability::ResourceId::new("localhost://UsersAI/orphan/journal"),
            elastos_runtime::capability::Action::Write,
            "orphan-restart".to_string(),
        )
        .await;
    let id = request.id.to_string();
    let token = plane.token().await;
    let client = reqwest::Client::new();
    let pending = client
        .get(format!("{}/api/capability/pending", plane.url))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        pending.contains(&id),
        "the live ask is missing before restart: {pending}"
    );
    assert!(pending.contains("orphan-restart"), "{pending}");
    plane.shutdown().await;
    let plane = home.plane().await;
    let token = plane.token().await;
    let pending = client
        .get(format!("{}/api/capability/pending", plane.url))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !pending.contains(&id),
        "restart restored the ask: {pending}"
    );
    assert!(!pending.contains("orphan-restart"), "{pending}");
    plane.shutdown().await;
}

#[tokio::test]
async fn two_agents_keep_their_own_roots_and_stop_retires_only_one() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let first = home.create_agent("A", &cid);
    let second = home.create_agent("B", &cid);
    let root =
        |id: &str| crate::auth::principal_stored_localhost_root(Some(&home.data), id).unwrap();
    let (first_root, second_root) = (root(&first), root(&second));
    assert!(
        first_root.starts_with("localhost://UsersAI/"),
        "{first_root}"
    );
    assert!(
        second_root.starts_with("localhost://UsersAI/"),
        "{second_root}"
    );
    assert_ne!(first_root, second_root);
    let plane = home.plane().await;
    let first_session = home.launch(&first, &dir).await;
    let second_session = home.launch(&second, &dir).await;
    assert!(
        capsule_live(&plane.url, &plane.secret, &first_session).await,
        "first agent is not running"
    );
    assert!(
        capsule_live(&plane.url, &plane.secret, &second_session).await,
        "second agent is not running"
    );
    super::super::gateway_home_runtime::stop_runtime_agent(&home.data, &first)
        .await
        .unwrap();
    assert!(!capsule_live(&plane.url, &plane.secret, &first_session).await);
    assert!(capsule_live(&plane.url, &plane.secret, &second_session).await);
    super::super::gateway_agents::end_live_agent(&home.data, &second)
        .await
        .unwrap();
    assert!(!capsule_live(&plane.url, &plane.secret, &second_session).await);
    let retired = crate::agents::retire(&home.data, &home.caller(), &second, 3).unwrap();
    assert!(retired.retired_at.is_some());
    let kept = crate::agents::stored_agent(&home.data, &home.owner, &first).unwrap();
    assert!(kept.record.retired_at.is_none());
    assert!(kept.active);
    plane.shutdown().await;
}

#[tokio::test]
async fn an_approved_plan_is_found_by_dispatch_in_this_process() {
    let home = Home::open();
    let plane = home.plane().await;
    let coords = crate::api::agent_plane::live_coords(&home.data)
        .await
        .unwrap();
    assert_eq!(coords.pid, std::process::id());
    let step = json!({"scheme": "localhost", "operation": "read", "request": {"path": "note"}});
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
        capability_manager: Arc::new(elastos_runtime::capability::CapabilityManager::new(
            Arc::new(elastos_runtime::capability::CapabilityStore::new()),
            Arc::new(elastos_runtime::primitives::audit::AuditLog::new()),
            Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
        )),
        pending_store: Arc::new(elastos_runtime::capability::PendingRequestStore::new(
            Arc::new(elastos_runtime::primitives::audit::AuditLog::new()),
        )),
        capsule_id: "capsule:s1".to_string(),
        session_id: "session:s1".to_string(),
        principal_id: Some("agent:s1".to_string()),
        manifest_capabilities: Vec::new(),
        data_dir: Some(home.data.clone()),
        launch: None,
        model_token_ceiling: None,
        model_budget: None,
        stop: None,
        plan_book: None,
    };
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        "plan-s1",
        "person:s1",
        &ctx,
        &step,
    )
    .unwrap();
    let found = crate::resource_bridge::dispatch_agent_plan_step(
        "plan-s1",
        "person:s1",
        "agent:s1",
        "capsule:s1",
        "session:s1",
        &home.data,
        &step,
    )
    .await;
    assert_ne!(found["code"].as_str(), Some("admission_missing"), "{found}");
    let missing = crate::resource_bridge::dispatch_agent_plan_step(
        "plan-absent",
        "person:s1",
        "agent:s1",
        "capsule:s1",
        "session:s1",
        &home.data,
        &step,
    )
    .await;
    assert_eq!(missing["code"], "admission_missing", "{missing}");
    plane.shutdown().await;
}

async fn guest_cause(body: &str, needle: &str) {
    let home = Home::open();
    let dir = home._temp.path().join("guest");
    let cid = sign_wat(&dir, body);
    let agent = home.create_agent("Guest", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let cause = gateway.cause(&session).await;
    assert!(cause.contains(needle), "{cause}");
    gateway.health().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_trapped_guest_leaves_the_gateway_up() {
    guest_cause(TRAP_BODY, "unreachable").await;
}

#[tokio::test]
async fn a_fuel_exhausted_guest_leaves_the_gateway_up() {
    guest_cause(FUEL_BODY, "fuel-exhausted").await;
}

#[tokio::test]
async fn a_memory_exhausted_guest_leaves_the_gateway_up() {
    guest_cause(MEMORY_BODY, "memory").await;
}

#[tokio::test]
async fn a_hung_guest_leaves_the_gateway_up() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Hung", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    for _ in 0..8 {
        gateway.health().await;
        assert!(
            capsule_live(&gateway.agent_url, &gateway.secret, &session).await,
            "a waiting guest ended on its own"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    super::super::gateway_home_runtime::stop_runtime_agent(&home.data, &agent)
        .await
        .unwrap();
    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    gateway.health().await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn agents_off_ends_the_guest_ensure_running_started() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Live", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    assert!(
        capsule_live(&gateway.agent_url, &gateway.secret, &session).await,
        "the guest was not live before Off"
    );
    let proof = home.context.proof_binding_id().unwrap().to_string();
    let mut state = crate::auth::load_auth_state(&home.data).unwrap();
    let owner = state
        .principals
        .iter_mut()
        .find(|principal| principal.principal_id == home.owner)
        .expect("the owner is stored");
    owner.proof_binding_id = proof;
    owner.role = crate::auth::RuntimePrincipalRole::Admin;
    crate::auth::save_auth_state(&home.data, &state, None).unwrap();
    let token = super::super::gateway_home_token::issue_home_projection_launch_token_with_context(
        &home.data,
        "system",
        "system",
        &home.context,
    )
    .unwrap();
    let response = reqwest::Client::new()
        .post(format!(
            "http://{}/api/apps/system/agents/disable",
            gateway.addr
        ))
        .header("host", gateway.addr.clone())
        .header("origin", "null")
        .header("x-elastos-home-token", token)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    port_closed(&gateway.agent_url).await;
    let named = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .audit
        .into_iter()
        .any(|event| {
            event.event_type == "agent.stopped"
                && event.session_id.as_deref() == Some(session.as_str())
        });
    assert!(named, "Off did not sign a stopped row for {session}");
    gateway.shutdown().await;
}

fn reexec(test_name: &str) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--test-threads=1", "--nocapture", test_name])
        .env("AGENT_PLANE_PANIC_CHILD", "1")
        .env("RUST_BACKTRACE", "1")
        .output()
        .unwrap()
}

fn measure(output: &std::process::Output) -> Value {
    use std::os::unix::process::ExitStatusExt;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .rev()
        .find(|line| line.starts_with("MEASURE "))
        .unwrap_or("");
    serde_json::from_str(line.trim_start_matches("MEASURE ")).unwrap_or_else(|_| {
        json!({
            "status": output.status.code(),
            "signal": output.status.signal(),
            "stdout": text,
            "stderr": String::from_utf8_lossy(&output.stderr),
        })
    })
}

fn child_ran(output: &std::process::Output, kind: &str) -> Value {
    let value = measure(output);
    assert!(
        output.status.success(),
        "{kind} child did not stay up: status {:?} signal {:?} measure {value} stderr {}",
        output.status.code(),
        output.status.signal(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["kind"], kind, "{value}");
    eprintln!("MEASURED {value}");
    if let Ok(path) = std::env::var("AGENT_PLANE_MEASURE_LOG") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(file, "{value}").unwrap();
    }
    value
}

/// A host call panics while the guest is inside it. The child records whether
/// this process stays up, whether that session ends, and whether the next
/// launch, stop and Home request still work.
#[tokio::test]
async fn a_panicking_host_call_leaves_the_session_and_home_up() {
    if std::env::var("AGENT_PLANE_PANIC_CHILD").as_deref() == Ok("1") {
        host_panic_child().await;
        return;
    }
    let output = reexec("a_panicking_host_call_leaves_the_session_and_home_up");
    let value = child_ran(&output, "host");
    assert_eq!(
        value["cause"], "Component run ended without publishing an outcome",
        "{value}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("planted host panic"),
        "the planted host panic never reached the child's stderr"
    );
    assert_eq!(value["session_ended"], true, "{value}");
    assert_eq!(value["next_live"], true, "{value}");
    assert_eq!(value["stop"], "ok", "{value}");
    assert_eq!(value["home"], 200, "{value}");
    assert_eq!(value["dirs_lock"], true, "{value}");
    assert_eq!(value["plan_status"], "instance ended", "{value}");
    assert_ne!(value["plan_status"], "completed", "{value}");
}

#[tokio::test]
async fn a_panicking_agent_route_leaves_home_serving() {
    if std::env::var("AGENT_PLANE_PANIC_CHILD").as_deref() == Ok("1") {
        route_panic_child().await;
        return;
    }
    let output = reexec("a_panicking_agent_route_leaves_home_serving");
    let value = child_ran(&output, "route");
    let panic_status = value["panic_status"].as_u64().expect("no panic status");
    assert!(
        panic_status == 0 || panic_status >= 500,
        "the panic route answered with a success status: {value}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("planted agent route panic"),
        "the planted route panic never reached the child's stderr"
    );
    assert_eq!(value["home"], 200, "{value}");
    assert_eq!(value["plane_health"], 200, "{value}");
}

#[tokio::test]
async fn a_panicking_agent_runtime_task_is_named_and_home_keeps_serving() {
    if std::env::var("AGENT_PLANE_PANIC_CHILD").as_deref() == Ok("1") {
        task_panic_child().await;
        return;
    }
    let output = reexec("a_panicking_agent_runtime_task_is_named_and_home_keeps_serving");
    let value = child_ran(&output, "task");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("planted agent runtime task panic"),
        "the planted task panic never reached the child's stderr"
    );
    assert_eq!(value["home"], 200, "{value}");
    assert_eq!(
        value["fault"],
        crate::api::agent_plane::TASK_ENDED,
        "{value}"
    );
    assert_eq!(
        value["launch"],
        crate::api::agent_plane::TASK_ENDED,
        "{value}"
    );
    assert_eq!(value["stop_already"], "ended", "{value}");
}

async fn host_panic_child() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let first = home.create_agent("Panic", &cid);
    let second = home.create_agent("Next", &cid);
    let gateway = Gateway::start(&home.data).await;
    crate::runtime::hold_planted_host_panic();
    crate::runtime::plant_host_panic();
    let session = home.launch(&first, &dir).await;
    let submitted = crate::api::gateway::submit_pending_agent_plan(
        &home.data,
        &home.owner,
        &first,
        &session,
        &session,
        &json!({
            "steps": [{
                "scheme": "availability",
                "operation": "status",
                "request": {}
            }]
        }),
        crate::auth::now_ts(),
    );
    crate::runtime::release_planted_host_panic();
    let submitted =
        submitted.expect("the pending step is stored before the host panic ends the session");
    let request_id = submitted["request_id"].as_str().unwrap().to_string();
    let cause = poll_cause(&gateway, &session).await;
    let plan_path = home
        .data
        .join("inspect-actions")
        .join(format!("{request_id}.json"));
    let plan: Value =
        serde_json::from_slice(&std::fs::read(&plan_path).expect("the pending step file")).unwrap();
    let plan_status = plan["status"].as_str().unwrap_or("").to_string();
    let next = home.launch(&second, &dir).await;
    let next_live = capsule_live(&gateway.agent_url, &gateway.secret, &next).await;
    let stop = super::super::gateway_home_runtime::stop_runtime_agent(&home.data, &second).await;
    let home_status = http_status(&format!("http://{}/healthz", gateway.addr)).await;
    println!(
        "MEASURE {}",
        json!({
            "kind": "host",
            "cause": cause,
            "session_ended": cause.is_some(),
            "next_live": next_live,
            "stop": stop.as_ref().map(|_| "ok").unwrap_or("err"),
            "stop_error": stop.as_ref().err().map(|error| error.to_string()),
            "home": home_status,
            "dirs_lock": crate::api::agent_plane::dirs_lock_works(),
            "plan_status": plan_status,
        })
    );
    gateway.shutdown().await;
}

async fn route_panic_child() {
    let home = Home::open();
    let gateway = Gateway::start(&home.data).await;
    let panic_status =
        http_status(&format!("{}/api/test/plane-route-panic", gateway.agent_url)).await;
    let plane_health = http_status(&format!("{}/api/health", gateway.agent_url)).await;
    let home_status = http_status(&format!("http://{}/healthz", gateway.addr)).await;
    println!(
        "MEASURE {}",
        json!({
            "kind": "route",
            "panic_status": panic_status,
            "plane_health": plane_health,
            "home": home_status,
            "fault": crate::api::agent_plane::task_fault(&home.data),
        })
    );
    gateway.shutdown().await;
}

async fn task_panic_child() {
    let home = Home::open();
    let gateway = Gateway::start(&home.data).await;
    crate::api::agent_plane::plant_task_panic();
    let mut fault = None;
    for _ in 0..100 {
        fault = crate::api::agent_plane::task_fault(&home.data);
        if fault.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let launch = super::super::gateway_home_runtime::launch_runtime_agent(
        &home.data,
        std::path::Path::new("."),
        "agent:absent",
        "grant",
    )
    .await;
    let stop =
        super::super::gateway_home_runtime::stop_runtime_agent(&home.data, "agent:absent").await;
    let home_status = http_status(&format!("http://{}/healthz", gateway.addr)).await;
    println!(
        "MEASURE {}",
        json!({
            "kind": "task",
            "fault": fault,
            "launch": launch.err().map(|error| error.to_string()),
            "stop_already": stop.ok().and_then(|outcome| outcome.already),
            "home": home_status,
        })
    );
    gateway.shutdown().await;
}

async fn poll_cause(gateway: &Gateway, session: &str) -> Option<String> {
    for _ in 0..200 {
        if let Some(cause) = capsule_cause(&gateway.agent_url, &gateway.secret, session).await {
            return Some(cause);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

async fn http_status(url: &str) -> u16 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    match client.get(url).send().await {
        Ok(response) => response.status().as_u16(),
        Err(_) => 0,
    }
}

#[tokio::test]
async fn a_stopped_plan_is_not_minted() {
    let home = Home::open();
    let flag = std::sync::Arc::new(crate::resource_bridge::ActivationStopFlag {
        requested: std::sync::atomic::AtomicBool::new(true),
        cancelled: std::sync::atomic::AtomicBool::new(false),
    });
    let step = json!({"scheme": "localhost", "operation": "read", "request": {"path": "note"}});
    let ctx = crate::resource_bridge::BridgeContext {
        provider_registry: Arc::new(elastos_runtime::provider::ProviderRegistry::new()),
        capability_manager: Arc::new(elastos_runtime::capability::CapabilityManager::new(
            Arc::new(elastos_runtime::capability::CapabilityStore::new()),
            Arc::new(elastos_runtime::primitives::audit::AuditLog::new()),
            Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
        )),
        pending_store: Arc::new(elastos_runtime::capability::PendingRequestStore::new(
            Arc::new(elastos_runtime::primitives::audit::AuditLog::new()),
        )),
        capsule_id: "capsule:stopped".to_string(),
        session_id: "session:stopped".to_string(),
        principal_id: Some("agent:stopped".to_string()),
        manifest_capabilities: Vec::new(),
        data_dir: Some(home.data.clone()),
        launch: None,
        model_token_ceiling: None,
        model_budget: None,
        stop: Some(flag),
        plan_book: None,
    };
    crate::resource_bridge::retain_agent_plan_dispatch_authority(
        "plan-stopped",
        "person:stopped",
        &ctx,
        &step,
    )
    .unwrap();
    let response = crate::resource_bridge::dispatch_agent_plan_step(
        "plan-stopped",
        "person:stopped",
        "agent:stopped",
        "capsule:stopped",
        "session:stopped",
        &home.data,
        &step,
    )
    .await;
    assert_eq!(response["code"], "stopped", "{response}");
    assert_eq!(
        crate::resource_bridge::plan_one_use_count(&home.data, "capsule:stopped"),
        0
    );
}

#[tokio::test]
async fn a_grant_with_no_live_session_is_refused_on_the_plane() {
    let home = Home::open();
    let plane = home.plane().await;
    let runtime =
        crate::api::agent_plane::plane_runtime(&home.data).expect("the plane is registered");
    assert!(runtime.instance_authority_is_set());
    let (store, _manager, _dir) = runtime
        .instance_authority_plane()
        .expect("the plane set its instance authority");
    let request = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string("capsule:not-live"),
            elastos_runtime::capability::ResourceId::new("localhost://UsersAI/notes/journal"),
            elastos_runtime::capability::Action::Write,
            "store a note".to_string(),
        )
        .await;
    let token = plane.token().await;
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/capability/grant", plane.url))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({"request_id": request.id.as_str(), "duration": "session"}))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(status.as_u16(), 409, "{text}");
    assert!(text.contains("the asking session has ended"), "{text}");
    plane.shutdown().await;
}

#[tokio::test]
async fn a_used_storage_grant_is_refused_after_stop_on_the_plane() {
    let home = Home::open();
    let plane = home.plane().await;
    let (store, manager, dir) = plane
        .runtime()
        .instance_authority_plane()
        .expect("the plane set its instance authority");
    let session = "capsule:stored";
    let resource =
        elastos_runtime::capability::ResourceId::new("localhost://UsersAI/notes/.AppData/journal");
    let request = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string(session),
            resource.clone(),
            elastos_runtime::capability::Action::Write,
            "write the journal".to_string(),
        )
        .await;
    let token = manager.grant(
        session,
        resource,
        elastos_runtime::capability::Action::Write,
        elastos_runtime::capability::TokenConstraints::default(),
        None,
    );
    store
        .grant_request(
            request.id.as_str(),
            token.clone(),
            elastos_runtime::capability::pending::GrantDuration::Session,
        )
        .await
        .unwrap();
    assert!(manager.can_still_validate(&token).await);
    crate::api::handlers::settle::settle_and_revoke(
        &store,
        &manager,
        Some(&dir),
        session,
        "stopped",
    )
    .await
    .unwrap();
    assert!(
        !manager.can_still_validate(&token).await,
        "a used storage grant still validated after stop on the plane"
    );
    plane.shutdown().await;
}

fn inbox_token(data: &Path, principal: &str, proof: &str) -> String {
    let now = crate::auth::now_ts();
    let grant = elastos_runtime::auth::AuthSessionGrantV1 {
        schema: elastos_runtime::auth::AuthSessionGrantV1::SCHEMA.to_string(),
        grant_id: format!("grant:{}", super::uuid_like_token()),
        session_id: format!("auth:{}", super::uuid_like_token()),
        principal_id: principal.to_string(),
        proof_binding_id: proof.to_string(),
        issued_at: now,
        expires_at: now + 12 * 60 * 60,
        apps: vec!["inbox".to_string()],
    };
    crate::auth::store_session_grant(data, grant.clone()).unwrap();
    super::super::gateway_home_token::issue_home_launch_token_for_auth_grant(data, "inbox", &grant)
        .unwrap()
}

async fn post_inbox(state: &super::GatewayState, token: &str, action_id: &str) -> (u16, String) {
    let request = super::test_browser_request("localhost:61180", "null")
        .method("POST")
        .uri("/api/apps/inbox/actions")
        .header("x-elastos-home-token", token)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            json!({ "action_id": action_id }).to_string(),
        ))
        .unwrap();
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let response =
        super::inbox_action(axum::extract::State(state.clone()), parts.headers, body).await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn the_owner_answer_is_refused_at_the_inbox_route() {
    let home = Home::open();
    let agent_id = home.create_agent("Notes", "bafkreia5notesl1");
    let root = crate::auth::stored_principal_record(&home.data, &agent_id)
        .unwrap()
        .unwrap()
        .localhost_root;
    let plane = home.plane().await;
    let session = "capsule:l1-live";
    plane
        .runtime()
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: agent_id.clone(),
            owner: home.owner.clone(),
            host_cid: REGISTRY_CID.to_string(),
            launch_id: "launch-l1".to_string(),
            session_id: session.to_string(),
        })
        .await;
    let (store, _, _) = plane
        .runtime()
        .instance_authority_plane()
        .expect("the plane set its instance authority");
    let resource = elastos_runtime::capability::ResourceId::new(format!("{root}/.AppData/journal"));
    let live = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string(session),
            resource.clone(),
            elastos_runtime::capability::Action::Write,
            "write the journal".to_string(),
        )
        .await;
    let ended = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string("capsule:l1-ended"),
            resource,
            elastos_runtime::capability::Action::Write,
            "the session has ended".to_string(),
        )
        .await;
    let owner_token = inbox_token(&home.data, &home.owner, &home.proof);
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "l1-other-owner",
    );
    let admin = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Admin"),
        crate::auth::RuntimePrincipalRole::Admin,
        "l1-other-admin",
    );
    let guest = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Guest"),
        crate::auth::RuntimePrincipalRole::Guest,
        "l1-guest",
    );
    let other_token = super::app_token_for_authority(&home.data, "inbox", &other);
    let admin_token = super::app_token_for_authority(&home.data, "inbox", &admin);
    let guest_token = super::app_token_for_authority(&home.data, "inbox", &guest);
    let state = super::test_state(&home.data);
    let action = format!("capability-deny-request:agent:{}", live.id.as_str());
    for (who, token, principal) in [
        ("other owner", &other_token, &other.principal_id),
        ("admin", &admin_token, &admin.principal_id),
        ("guest", &guest_token, &guest.principal_id),
    ] {
        let (status, body) = post_inbox(&state, token, &action).await;
        assert_eq!(status, 403, "{who}: {body}");
        assert!(
            body.contains("belongs to a different principal"),
            "{who}: {body}"
        );
        assert!(body.contains(principal), "{who}: {body}");
        assert!(body.contains("Notes"), "{who}: {body}");
        assert!(
            !body.contains("the asking session has ended"),
            "{who}: {body}"
        );
    }
    let ended_action = format!("capability-deny-request:agent:{}", ended.id.as_str());
    let (status, body) = post_inbox(&state, &owner_token, &ended_action).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("the asking session has ended"), "{body}");
    assert!(!body.contains("belongs to a different principal"), "{body}");
    let (status, body) = post_inbox(&state, &owner_token, &action).await;
    assert_eq!(status, 200, "{body}");
    plane.shutdown().await;
}

async fn http_approve(addr: &str, token: &str, request_id: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/apps/inbox/actions"))
        .header("host", addr)
        .header("origin", "null")
        .header("x-elastos-home-token", token)
        .header("content-type", "application/json")
        .body(
            json!({
                "action_id": format!("capability-approve-request:agent:{request_id}"),
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (status, text)
}

fn grant_events(data: &Path, request_id: &str) -> Vec<elastos_runtime::auth::RuntimeAuditEventV1> {
    crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| {
            event.challenge_id.as_deref() == Some(request_id)
                && event.event_type.starts_with("agent.grant.")
        })
        .collect()
}

fn assert_copied(
    event: &elastos_runtime::auth::RuntimeAuditEventV1,
    owner: &str,
    session: &str,
    agent: &str,
) {
    assert_eq!(event.principal_id.as_deref(), Some(owner));
    assert_eq!(event.session_id.as_deref(), Some(session));
    assert_eq!(event.capsule_id.as_deref(), Some(agent));
    let reason: serde_json::Value = serde_json::from_str(&event.reason).unwrap();
    for key in ["principal", "session", "agent", "capsule", "resource"] {
        let text = reason[key].as_str().unwrap_or("");
        assert!(!text.is_empty(), "{key} is blank in {}", event.reason);
    }
    assert_eq!(reason["principal"], owner);
    assert_eq!(reason["session"], session);
    assert_eq!(reason["agent"], agent);
    assert_eq!(reason["capsule"], agent);
}

fn grant_audit(data: &Path, request_id: &str) -> Vec<(String, String)> {
    crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| {
            event.challenge_id.as_deref() == Some(request_id)
                && event.event_type.starts_with("agent.grant.")
        })
        .map(|event| (event.event_type, event.result))
        .collect()
}

async fn usable_grant(data: &Path, request_id: &str) -> bool {
    let Some(runtime) = crate::api::agent_plane::plane_runtime(data) else {
        return false;
    };
    let Some((store, manager, _)) = runtime.instance_authority_plane() else {
        return false;
    };
    let Some(request) = store.get_request(request_id).await else {
        return false;
    };
    let Some(token) = request.granted_token() else {
        return false;
    };
    request.is_granted() && manager.can_still_validate(token).await
}

async fn plant_pending(home: &Home, session: &str, agent_id: &str) -> String {
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).expect("plane");
    runtime
        .insert_agent_session_for_test(crate::runtime::AgentSessionRecord {
            agent_id: agent_id.to_string(),
            owner: home.owner.clone(),
            host_cid: REGISTRY_CID.to_string(),
            launch_id: format!("launch-{session}"),
            session_id: session.to_string(),
        })
        .await;
    let root = crate::auth::stored_principal_record(&home.data, agent_id)
        .unwrap()
        .unwrap()
        .localhost_root;
    let (store, _, _) = runtime.instance_authority_plane().unwrap();
    let request = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string(session),
            elastos_runtime::capability::ResourceId::new(format!("{root}/.AppData/journal")),
            elastos_runtime::capability::Action::Write,
            "write the journal".to_string(),
        )
        .await;
    request.id.to_string()
}

#[tokio::test]
async fn an_audit_failure_on_the_inbox_mints_nothing() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreiauditfail");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:audit-fail", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_fault(&home.data, false);
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert_eq!(body, "Nothing ran. Approve this ask again.");
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    assert!(!body.contains("auth-state"), "{body}");
    assert!(
        grant_audit(&home.data, &request_id).is_empty(),
        "a failed approval row must not exist"
    );
    assert!(!usable_grant(&home.data, &request_id).await);
    let (store, _, _) = crate::api::agent_plane::plane_runtime(&home.data)
        .unwrap()
        .instance_authority_plane()
        .unwrap();
    assert!(store.get_request(&request_id).await.unwrap().is_pending());
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_crash_before_the_send_is_not_sent() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreicrashmint");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:crash-mint", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_kind(&home.data, "before-send");
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("crash before the send"), "{body}");
    let rows = grant_audit(&home.data, &request_id);
    assert_eq!(
        rows,
        vec![("agent.grant.approved".to_string(), "approved".to_string())],
        "{rows:?}"
    );
    assert!(!usable_grant(&home.data, &request_id).await);
    super::super::gateway_inbox::settle_unminted_agent_grants(&home.data)
        .await
        .unwrap();
    let closed = grant_events(&home.data, &request_id);
    let settled = closed
        .iter()
        .find(|event| event.result == "not_sent")
        .expect("crash before the send");
    assert!(
        closed.iter().all(|event| event.result != "not_granted"),
        "{closed:?}"
    );
    assert_copied(settled, &home.owner, "capsule:crash-mint", &agent);
    super::super::gateway_inbox::settle_unminted_agent_grants(&home.data)
        .await
        .unwrap();
    assert_eq!(
        grant_events(&home.data, &request_id)
            .iter()
            .filter(|event| event.result == "not_sent")
            .count(),
        1
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_plane_refusal_signs_that_the_grant_was_not_given() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreirefused");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:not-live-inbox", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_eq!(status, 409, "{body}");
    let rows = grant_audit(&home.data, &request_id);
    assert!(rows.iter().any(|row| row.1 == "approved"), "{rows:?}");
    assert!(rows.iter().any(|row| row.1 == "not_granted"), "{rows:?}");
    assert!(!usable_grant(&home.data, &request_id).await);
    gateway.shutdown().await;
}

#[tokio::test]
async fn two_inbox_approvals_mint_one_grant() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Notes", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let request_id = plant_pending(&home, &session, &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    let first = http_approve(&gateway.addr, &token, &request_id);
    let second = http_approve(&gateway.addr, &token, &request_id);
    let (left, right) = tokio::join!(first, second);
    let statuses = [left.0, right.0];
    assert!(
        statuses.contains(&200),
        "neither approval minted: {left:?} {right:?}"
    );
    let loser = if left.0 == 200 { &right } else { &left };
    assert_eq!(
        loser.0, 409,
        "the second approval is a conflict: {left:?} {right:?}"
    );
    assert!(
        loser.1.contains("not_granted"),
        "the loser names not_granted: {loser:?}"
    );
    let rows = grant_audit(&home.data, &request_id);
    assert_eq!(
        rows.iter().filter(|row| row.1 == "approved").count(),
        1,
        "{rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.1 == "not_granted"),
        "the live grant was marked not granted: {rows:?}"
    );
    assert!(
        usable_grant(&home.data, &request_id).await,
        "the one grant is not usable"
    );
    assert_eq!(
        rows.iter().filter(|row| row.1 == "minted").count(),
        1,
        "{rows:?}"
    );
    gateway.shutdown().await;
    let restarted = Gateway::start(&home.data).await;
    let kept = grant_audit(&home.data, &request_id);
    assert_eq!(
        kept.iter().filter(|row| row.1 == "minted").count(),
        1,
        "{kept:?}"
    );
    assert!(
        !kept
            .iter()
            .any(|row| row.1 == "not_granted" || row.1 == "unresolved" || row.1 == "not_sent"),
        "a minted grant was settled again: {kept:?}"
    );
    restarted.shutdown().await;
}

#[tokio::test]
async fn a_restart_settles_an_approved_grant_that_was_never_minted() {
    let home = Home::open();
    crate::auth::append_audit_event(
        &home.data,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: "audit:plant-unminted".to_string(),
            event_type: "agent.grant.approved".to_string(),
            principal_id: Some(home.owner.clone()),
            proof_binding_id: None,
            session_id: Some("session-plant".to_string()),
            challenge_id: Some("req-unminted".to_string()),
            capsule_id: Some("agent-plant".to_string()),
            result: "approved".to_string(),
            reason: serde_json::json!({
                "cause": "approved",
                "principal": home.owner,
                "session": "session-plant",
                "agent": "agent-plant",
                "capsule": "agent-plant",
                "resource": "localhost://UsersAI/notes/journal",
            })
            .to_string(),
            occurred_at: 1,
            signer_did: None,
            signature: None,
        },
    )
    .unwrap();
    let gateway = Gateway::start(&home.data).await;
    let rows = grant_events(&home.data, "req-unminted");
    let settled = rows
        .iter()
        .find(|event| event.result == "not_sent")
        .expect("an approved row that was never sent");
    assert!(rows.iter().all(|event| event.result != "not_granted"));
    assert_copied(settled, &home.owner, "session-plant", "agent-plant");
    gateway.shutdown().await;
}

#[tokio::test]
async fn an_effect_held_across_turn_off_is_not_signed_ok() {
    let home = Home::open();
    let plane = home.plane().await;
    let runtime = plane.runtime();
    runtime.bind_plan_instance("session-held", "agent-held");
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &runtime.plan_book(),
        "session-held",
        "agent-held",
        "step-held",
    )
    .expect("the effect hold");
    crate::agent_record_audit::append_agent_row(
        &home.data,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: "audit:stopping-held".to_string(),
            event_type: "agent.stopped".to_string(),
            principal_id: Some(home.owner.clone()),
            proof_binding_id: None,
            session_id: Some("session-held".to_string()),
            challenge_id: None,
            capsule_id: None,
            result: "stopping".to_string(),
            reason: "effect held".to_string(),
            occurred_at: 1,
            signer_did: None,
            signature: None,
        },
    )
    .unwrap();
    stop_plane(&home.data).await;
    assert!(
        crate::api::agent_plane::plane_runtime(&home.data).is_some(),
        "the plane left while the effect was in flight"
    );
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    let oks = |data: &Path| {
        crate::auth::load_auth_state(data)
            .unwrap()
            .audit
            .into_iter()
            .filter(|event| {
                event.event_type == "agent.stopped"
                    && event.result == "ok"
                    && event.session_id.as_deref() == Some("session-held")
            })
            .count()
    };
    assert_eq!(
        oks(&home.data),
        0,
        "ok was signed while the effect was held"
    );
    assert!(runtime.plan_effect_inflight("session-held"));
    guard.release();
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert_eq!(oks(&home.data), 1);
    assert!(crate::api::agent_plane::plane_runtime(&home.data).is_none());
}

fn enable_ok_count(data: &Path) -> usize {
    crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| event.event_type == "agent.records.enable" && event.result == "ok")
        .count()
}

async fn plain_launch_refused(data: &Path) {
    crate::api::agent_plane::release_dir_for_test(data);
    let coords = wait_coords(data).await;
    let token = shell_token(&coords.api_url, &coords.attach_secret).await;
    let response = reqwest::Client::new()
        .post(format!("{}/api/capsules", coords.api_url))
        .header("authorization", format!("Bearer {token}"))
        .json(&json!({ "path": "/tmp/not-an-agent" }))
        .send()
        .await
        .unwrap();
    let status = response.status();
    let text = response.text().await.unwrap();
    assert_eq!(status.as_u16(), 400, "{text}");
    assert!(
        text.contains("this runtime launches a stored agent"),
        "{text}"
    );
}

fn stopped_ok_count(data: &Path, session: &str) -> usize {
    crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| {
            event.event_type == "agent.stopped"
                && event.result == "ok"
                && event.session_id.as_deref() == Some(session)
        })
        .count()
}

fn system_token(home: &Home) -> String {
    let proof = home.context.proof_binding_id().unwrap().to_string();
    let mut state = crate::auth::load_auth_state(&home.data).unwrap();
    let owner = state
        .principals
        .iter_mut()
        .find(|principal| principal.principal_id == home.owner)
        .expect("owner");
    owner.proof_binding_id = proof;
    owner.role = crate::auth::RuntimePrincipalRole::Admin;
    crate::auth::save_auth_state(&home.data, &state, None).unwrap();
    super::super::gateway_home_token::issue_home_projection_launch_token_with_context(
        &home.data,
        "system",
        "system",
        &home.context,
    )
    .unwrap()
}

async fn home_http(addr: &str, token: &str, method: reqwest::Method, path: &str) -> (u16, String) {
    let mut request = reqwest::Client::new()
        .request(method.clone(), format!("http://{addr}{path}"))
        .header("host", addr)
        .header("origin", "null")
        .header("x-elastos-home-token", token);
    if method != reqwest::Method::GET {
        request = request
            .header("content-type", "application/json")
            .body("{}");
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

fn cause_of(data: &Path, request_id: &str, result: &str) -> String {
    let event = grant_events(data, request_id)
        .into_iter()
        .find(|event| event.result == result)
        .unwrap_or_else(|| panic!("no {result} row"));
    serde_json::from_str::<serde_json::Value>(&event.reason).unwrap()["cause"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[tokio::test]
async fn a_crash_after_the_mint_is_unresolved_and_the_guest_file_stays() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Notes", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let request_id = plant_pending(&home, &session, &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_kind(&home.data, "after-mint");
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("crash after the mint"), "{body}");
    assert!(usable_grant(&home.data, &request_id).await);
    let root = crate::auth::stored_principal_record(&home.data, &agent)
        .unwrap()
        .unwrap()
        .localhost_root;
    let target = format!("{root}/Documents/guest.txt");
    let path = elastos_common::localhost::rooted_localhost_fs_path(&home.data, &target).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    crate::auth::write_principal_root_object(&home.data, &agent, &root, &target, &path, b"guest")
        .unwrap();
    super::super::gateway_inbox::settle_unminted_agent_grants(&home.data)
        .await
        .unwrap();
    let rows = grant_events(&home.data, &request_id);
    let settled = rows
        .iter()
        .find(|event| event.result == "unresolved")
        .expect("unresolved");
    assert_eq!(
        cause_of(&home.data, &request_id, "unresolved"),
        "crash after the mint"
    );
    assert!(rows.iter().all(|event| event.result != "not_granted"));
    assert_copied(settled, &home.owner, &session, &agent);
    assert!(path.is_file());
    assert!(!std::fs::read(&path).unwrap().is_empty());
    assert_eq!(
        crate::auth::read_principal_root_object(&home.data, &agent, &root, &target, &path).unwrap(),
        b"guest"
    );
    assert!(usable_grant(&home.data, &request_id).await);
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_minted_row_is_unresolved_and_the_grant_stays() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Notes", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let request_id = plant_pending(&home, &session, &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_kind(&home.data, "minted-row");
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("the minted row failed"), "{body}");
    let rows = grant_audit(&home.data, &request_id);
    assert!(
        !rows
            .iter()
            .any(|row| row.1 == "minted" || row.1 == "not_granted"),
        "{rows:?}"
    );
    assert_eq!(
        cause_of(&home.data, &request_id, "unresolved"),
        "the minted row failed"
    );
    assert!(usable_grant(&home.data, &request_id).await);
    let copied = grant_events(&home.data, &request_id)
        .into_iter()
        .find(|event| event.result == "unresolved")
        .unwrap();
    assert_copied(&copied, &home.owner, &session, &agent);
    super::super::gateway_inbox::settle_unminted_agent_grants(&home.data)
        .await
        .unwrap();
    assert_eq!(
        grant_events(&home.data, &request_id)
            .iter()
            .filter(|event| event.result == "unresolved")
            .count(),
        1
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_plane_timeout_is_unresolved() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreitimeout");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:timeout", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_kind(&home.data, "timeout");
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("the plane timed out"), "{body}");
    let rows = grant_audit(&home.data, &request_id);
    assert!(rows.iter().any(|row| row.1 == "sent"), "{rows:?}");
    assert!(!rows.iter().any(|row| row.1 == "not_granted"), "{rows:?}");
    assert_eq!(
        cause_of(&home.data, &request_id, "unresolved"),
        "the plane timed out"
    );
    let copied = grant_events(&home.data, &request_id)
        .into_iter()
        .find(|event| event.result == "unresolved")
        .unwrap();
    assert_copied(&copied, &home.owner, "capsule:timeout", &agent);
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_grant_settle_does_not_refuse_the_home() {
    let home = Home::open();
    crate::auth::append_audit_event(
        &home.data,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: "audit:plant-settle-fail".to_string(),
            event_type: "agent.grant.approved".to_string(),
            principal_id: Some(home.owner.clone()),
            proof_binding_id: None,
            session_id: Some("session-settle".to_string()),
            challenge_id: Some("req-settle-fail".to_string()),
            capsule_id: Some("agent-settle".to_string()),
            result: "approved".to_string(),
            reason: serde_json::json!({
                "cause": "approved",
                "principal": home.owner,
                "session": "session-settle",
                "agent": "agent-settle",
                "capsule": "agent-settle",
                "resource": "localhost://UsersAI/notes/journal",
            })
            .to_string(),
            occurred_at: 1,
            signer_did: None,
            signature: None,
        },
    )
    .unwrap();
    super::seams::arm_grant_fault(&home.data, false);
    let gateway = Gateway::start(&home.data).await;
    gateway.health().await;
    assert!(grant_events(&home.data, "req-settle-fail")
        .iter()
        .all(|event| event.result != "not_sent" && event.result != "not_granted"));
    gateway.shutdown().await;
    let again = Gateway::start(&home.data).await;
    let settled = grant_events(&home.data, "req-settle-fail")
        .into_iter()
        .find(|event| event.result == "not_sent")
        .expect("the next start settles the open row");
    assert_copied(&settled, &home.owner, "session-settle", "agent-settle");
    again.shutdown().await;
}

struct IdleCompute;

#[async_trait::async_trait]
impl elastos_compute::ComputeProvider for IdleCompute {
    async fn load(
        &self,
        _: &std::path::Path,
        _: elastos_common::CapsuleManifest,
    ) -> elastos_common::Result<elastos_compute::CapsuleHandle> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn start(&self, _: &elastos_compute::CapsuleHandle) -> elastos_common::Result<()> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn stop(&self, _: &elastos_compute::CapsuleHandle) -> elastos_common::Result<()> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn status(
        &self,
        _: &elastos_compute::CapsuleHandle,
    ) -> elastos_common::Result<elastos_common::CapsuleStatus> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    async fn info(
        &self,
        _: &elastos_compute::CapsuleHandle,
    ) -> elastos_common::Result<elastos_compute::CapsuleInfo> {
        Err(elastos_common::ElastosError::InvalidManifest("idle".into()))
    }

    fn supports(&self, _: &elastos_common::CapsuleType) -> bool {
        false
    }
}

#[tokio::test]
async fn off_then_on_waits_until_the_old_plane_is_idle() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Live", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    runtime.bind_plan_instance(&session, &agent);
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &runtime.plan_book(),
        &session,
        &agent,
        "step-held",
    )
    .expect("effect hold");
    let token = system_token(&home);
    let (off, off_body) = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/disable",
    )
    .await;
    assert_eq!(off, 200, "{off_body}");
    let before_enable = std::fs::read(crate::agents::agent_file_path(&home.data).unwrap()).unwrap();
    let enable_ok_before = enable_ok_count(&home.data);
    assert!(!crate::agents::home_enabled(&home.data));
    let (on, on_body) = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/enable",
    )
    .await;
    assert_eq!(on, 409, "{on_body}");
    assert!(
        on_body.contains("the previous agent runtime is still stopping"),
        "{on_body}"
    );
    let after_refuse = std::fs::read(crate::agents::agent_file_path(&home.data).unwrap()).unwrap();
    assert_eq!(
        after_refuse, before_enable,
        "a refused start does not write the file"
    );
    assert!(!crate::agents::home_enabled(&home.data));
    assert_eq!(enable_ok_count(&home.data), enable_ok_before);
    let started = crate::api::agent_plane::start(&home.data, None).await;
    let error = started.expect_err("start while the old plane is busy");
    assert!(
        error
            .to_string()
            .contains("the previous agent runtime is still stopping"),
        "{error}"
    );
    let _ = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::GET,
        "/api/apps/system/agents",
    )
    .await;
    assert_eq!(stopped_ok_count(&home.data, &session), 0);
    let other = Home::open();
    let other_gateway = Gateway::start(&other.data).await;
    let mine = crate::api::agent_plane::watched_runtimes(&home.data);
    let theirs = crate::api::agent_plane::watched_runtimes(&other.data);
    assert!(!mine.is_empty() && !theirs.is_empty());
    assert!(mine.iter().all(|runtime| {
        theirs
            .iter()
            .all(|other_runtime| !Arc::ptr_eq(runtime, other_runtime))
    }));
    assert_eq!(stopped_ok_count(&home.data, &session), 0);
    guard.release();
    let (again, again_body) = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/enable",
    )
    .await;
    assert_eq!(again, 200, "{again_body}");
    assert!(crate::agents::home_enabled(&home.data));
    assert_eq!(enable_ok_count(&home.data), enable_ok_before + 1);
    let _ = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::GET,
        "/api/apps/system/agents",
    )
    .await;
    assert_eq!(stopped_ok_count(&home.data, &session), 1);
    stop_plane(&home.data).await;
    gateway.shutdown().await;
    other_gateway.shutdown().await;
}

#[tokio::test]
async fn a_live_plane_does_not_hide_a_retiring_effect_or_stop() {
    let home = Home::open();
    let plane = home.plane().await;
    let storage = home.data.join("shadow-storage");
    std::fs::create_dir_all(&storage).unwrap();
    let retiring = Arc::new(crate::runtime::Runtime::new(
        Arc::new(
            elastos_storage::providers::LocalFSProvider::new(storage)
                .await
                .unwrap(),
        ),
        Arc::new(IdleCompute),
    ));
    let session = "shadow-session";
    retiring.bind_plan_instance(session, "agent-shadow");
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &retiring.plan_book(),
        session,
        "agent-shadow",
        "step-shadow",
    )
    .expect("effect hold");
    retiring
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.to_string(),
            name: "shadow".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.to_string(),
            principal: Some("agent-shadow".to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
    crate::api::agent_plane::plant_retiring_runtime(&home.data, Arc::clone(&retiring));
    crate::agent_record_audit::append_agent_row(
        &home.data,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: "audit:shadow-stopping".to_string(),
            event_type: "agent.stopped".to_string(),
            principal_id: Some(home.owner.clone()),
            proof_binding_id: None,
            session_id: Some(session.to_string()),
            challenge_id: None,
            capsule_id: None,
            result: "stopping".to_string(),
            reason: "both halves".to_string(),
            occurred_at: 1,
            signer_did: None,
            signature: None,
        },
    )
    .unwrap();
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert_eq!(stopped_ok_count(&home.data, session), 0, "effect half");
    guard.release();
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert_eq!(stopped_ok_count(&home.data, session), 0, "stop half");
    retiring.unregister_capsule(session).await;
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert_eq!(stopped_ok_count(&home.data, session), 1);
    assert!(crate::api::agent_plane::watched_runtimes(&home.data)
        .iter()
        .all(|runtime| !Arc::ptr_eq(runtime, &retiring)));
    plane.shutdown().await;
}

#[tokio::test]
async fn two_enables_at_once_share_one_plane() {
    let home = Home::open();
    let gateway = Gateway::start(&home.data).await;
    let token = system_token(&home);
    let (off, off_body) = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/disable",
    )
    .await;
    assert_eq!(off, 200, "{off_body}");
    let first = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/enable",
    );
    let second = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/enable",
    );
    let (left, right) = tokio::join!(first, second);
    assert_eq!(left.0, 200, "{left:?}");
    assert_eq!(right.0, 200, "{right:?}");
    assert!(
        left.1.contains("true") && right.1.contains("true"),
        "{left:?} {right:?}"
    );
    assert!(crate::agents::home_enabled(&home.data));
    assert_eq!(
        crate::api::agent_plane::watched_runtimes(&home.data).len(),
        1
    );
    let coords = wait_coords(&home.data).await;
    plain_launch_refused(&home.data).await;
    let still = crate::api::agent_plane::live_coords(&home.data)
        .await
        .expect("the one plane kept its coordinates");
    assert_eq!(still.api_url, coords.api_url);
    gateway.shutdown().await;
}

#[tokio::test]
async fn enable_racing_startup_shares_one_plane() {
    let home = Home::open();
    let gateway = Gateway::start(&home.data).await;
    stop_plane(&home.data).await;
    assert!(crate::agents::home_enabled(&home.data));
    assert!(crate::api::agent_plane::plane_runtime(&home.data).is_none());
    let token = system_token(&home);
    let enable = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/enable",
    );
    let startup = crate::api::agent_plane::ensure_running(&home.data, None);
    let (http, started) = tokio::join!(enable, startup);
    assert_eq!(http.0, 200, "{http:?}");
    assert!(http.1.contains("true"), "{http:?}");
    started.expect("startup shares the enable");
    assert_eq!(
        crate::api::agent_plane::watched_runtimes(&home.data).len(),
        1
    );
    plain_launch_refused(&home.data).await;
    gateway.shutdown().await;
}

#[tokio::test]
async fn disable_racing_list_keeps_the_stopping_plane() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let agent = home.create_agent("Live", &cid);
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    runtime.bind_plan_instance(&session, &agent);
    let guard = crate::runtime::Runtime::try_enter_plan_effect(
        &runtime.plan_book(),
        &session,
        &agent,
        "step-held",
    )
    .expect("effect hold");
    plain_launch_refused(&home.data).await;
    crate::api::agent_plane::arm_stop_gap();
    let token = system_token(&home);
    let disable = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::POST,
        "/api/apps/system/agents/disable",
    );
    let listing = async {
        let mut saw_plane = false;
        for _ in 0..40 {
            let _ = home_http(
                &gateway.addr,
                &token,
                reqwest::Method::GET,
                "/api/apps/system/agents",
            )
            .await;
            if !crate::api::agent_plane::watched_runtimes(&home.data).is_empty() {
                saw_plane = true;
            }
            assert_eq!(stopped_ok_count(&home.data, &session), 0);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        saw_plane
    };
    let ((off, off_body), saw_plane) = tokio::join!(disable, listing);
    assert_eq!(off, 200, "{off_body}");
    assert!(saw_plane, "the list ran while neither plane was registered");
    assert_eq!(stopped_ok_count(&home.data, &session), 0);
    guard.release();
    let _ = home_http(
        &gateway.addr,
        &token,
        reqwest::Method::GET,
        "/api/apps/system/agents",
    )
    .await;
    assert_eq!(stopped_ok_count(&home.data, &session), 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_pending_plan_stays_when_its_capsule_is_still_running() {
    let home = Home::open();
    let storage = home.data.join("still-running");
    std::fs::create_dir_all(&storage).unwrap();
    let runtime = Arc::new(crate::runtime::Runtime::new(
        Arc::new(
            elastos_storage::providers::LocalFSProvider::new(storage)
                .await
                .unwrap(),
        ),
        Arc::new(IdleCompute),
    ));
    let capsule = "capsule:still-running";
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: capsule.to_string(),
            name: "still".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: "session:still".to_string(),
            principal: Some(home.owner.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    crate::api::agent_plane::plant_retiring_runtime(&home.data, Arc::clone(&runtime));
    let plan = serde_json::json!({
        "steps": [{ "scheme": "availability", "operation": "status", "request": {} }]
    });
    let created = super::super::gateway_inspect_actions::submit_pending_agent_plan(
        &home.data,
        &home.owner,
        "agent:v2:0123456789abcdef0123456789abcdef",
        capsule,
        "session:still",
        &plan,
        1,
    )
    .unwrap();
    let request_id = created["request_id"].as_str().unwrap().to_string();
    super::super::gateway_inspect_actions::settle_agent_plans_lost_before_start(&home.data)
        .unwrap();
    let stored = std::fs::read_dir(home.data.join("inspect-actions"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find_map(|entry| {
            let body = std::fs::read(entry.path()).ok()?;
            let value: serde_json::Value = serde_json::from_slice(&body).ok()?;
            (value["request_id"].as_str() == Some(request_id.as_str())).then_some(value)
        })
        .expect("the pending plan");
    assert_eq!(stored["status"], "pending");
}

fn passkey_context(auth: &super::TestPasskeyAuthority) -> HomeLaunchTokenContext {
    HomeLaunchTokenContext::for_test(
        auth.principal_id.clone(),
        auth.session_id.clone(),
        Some(auth.proof_binding_id.clone()),
        auth.grant_id.clone(),
        crate::auth::PrincipalKind::Human,
    )
}

fn create_owned_agent(data: &Path, auth: &super::TestPasskeyAuthority, cid: &str) -> String {
    let record = crate::auth::stored_principal_record(data, &auth.principal_id)
        .unwrap()
        .unwrap();
    crate::auth::store_test_principal_root_protection_for(
        data,
        &auth.principal_id,
        &record.localhost_root,
    );
    let caller = crate::agents::Caller {
        principal_id: &auth.principal_id,
        proof_binding_id: &auth.proof_binding_id,
        session_id: &auth.session_id,
    };
    let id = crate::agents::create(
        data,
        &caller,
        &crate::agents::CreateRequest {
            display_name: "Owner".to_string(),
            agent_host: HOST.to_string(),
            request_id: "request-Owner".to_string(),
        },
        |host| {
            Ok(
                crate::agent_admission::VerifiedAgentHost::unchecked_for_test(
                    host,
                    REGISTRY_CID,
                    cid,
                ),
            )
        },
        1,
    )
    .unwrap()
    .agent_id;
    crate::agents::set_active(data, &caller, &id, true, 1).unwrap();
    id
}

async fn post_json(addr: &str, token: &str, path: &str, body: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header("host", addr)
        .header("origin", "null")
        .header("x-elastos-home-token", token)
        .header("content-type", "application/json")
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

fn plan_file(data: &Path, request_id: &str) -> serde_json::Value {
    let path = data
        .join("inspect-actions")
        .join(format!("{request_id}.json"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn stop_cause(data: &Path, agent_id: &str, event_type: &str) -> (String, String, String) {
    let event = crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .find(|event| {
            if event.event_type != event_type {
                return false;
            }
            let reason: serde_json::Value =
                serde_json::from_str(&event.reason).unwrap_or(json!({}));
            event.capsule_id.as_deref() == Some(agent_id)
                || reason["agent_id"].as_str() == Some(agent_id)
        })
        .unwrap_or_else(|| panic!("no {event_type} row"));
    let reason: serde_json::Value = serde_json::from_str(&event.reason).unwrap();
    (
        event.principal_id.unwrap_or_default(),
        reason["cause"].as_str().unwrap_or("").to_string(),
        event.capsule_id.clone().unwrap_or_default(),
    )
}

fn step_plan() -> serde_json::Value {
    json!({ "steps": [{ "scheme": "availability", "operation": "status", "request": {} }] })
}

#[tokio::test]
async fn demotion_stops_the_running_agent_and_closes_its_plans() {
    let home = Home::open();
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-owner",
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-other",
    );
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let context = passkey_context(&owner);
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data, &agent, HOST, &context,
    )
    .unwrap();
    let session =
        super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, &agent, &grant)
            .await
            .unwrap()
            .session_id;
    assert!(capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    let root = crate::auth::stored_principal_record(&home.data, &agent)
        .unwrap()
        .unwrap()
        .localhost_root;
    let (store, _, _) = runtime.instance_authority_plane().unwrap();
    let ask = store
        .create_request_with_reason(
            elastos_runtime::session::SessionId::from_string(&session),
            elastos_runtime::capability::ResourceId::new(format!("{root}/.AppData/journal")),
            elastos_runtime::capability::Action::Write,
            "write the journal".to_string(),
        )
        .await;
    let now = crate::auth::now_ts();
    let pending = super::super::gateway_inspect_actions::submit_pending_agent_plan(
        &home.data,
        &owner.principal_id,
        &agent,
        HOST,
        &session,
        &step_plan(),
        now,
    )
    .unwrap();
    let inflight = super::super::gateway_inspect_actions::submit_pending_agent_plan(
        &home.data,
        &owner.principal_id,
        &agent,
        HOST,
        &session,
        &step_plan(),
        now + 1,
    )
    .unwrap();
    let pending_id = pending["request_id"].as_str().unwrap().to_string();
    let inflight_id = inflight["request_id"].as_str().unwrap().to_string();
    let mut flying = plan_file(&home.data, &inflight_id);
    flying["status"] = json!("dispatching");
    std::fs::write(
        home.data
            .join("inspect-actions")
            .join(format!("{inflight_id}.json")),
        serde_json::to_vec_pretty(&flying).unwrap(),
    )
    .unwrap();
    let (blocked, blocked_body) = post_json(
        &gateway.addr,
        &other.system_token,
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(blocked, 409, "{blocked_body}");
    assert!(capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let pending_stored = plan_file(&home.data, &pending_id);
    assert_eq!(
        pending_stored["status"], "owner demoted",
        "{pending_stored}"
    );
    assert_eq!(pending_stored["audit_recorded"], true, "{pending_stored}");
    // A claimed dispatching step is not overwritten as "owner demoted"; it
    // stays for the stop settle path (unknown / unresolved) once.
    let flying_stored = plan_file(&home.data, &inflight_id);
    assert_ne!(flying_stored["status"], "owner demoted", "{flying_stored}");
    assert_ne!(flying_stored["status"], "completed", "{flying_stored}");
    let (signer, cause, _) = stop_cause(&home.data, &agent, "agent.stop.requested");
    assert_eq!(signer, other.principal_id);
    assert_eq!(cause, "owner demoted");
    let (stopped_by, stopped_cause, capsule) = stop_cause(&home.data, &agent, "agent.stopped");
    assert_eq!(stopped_by, other.principal_id);
    assert_eq!(stopped_cause, "owner demoted");
    assert_eq!(capsule, HOST);
    assert!(!store
        .get_request(ask.id.as_str())
        .await
        .unwrap()
        .is_pending());
    let guest_inbox = inbox_token(&home.data, &owner.principal_id, &owner.proof_binding_id);
    let (seen, summary) = home_http(
        &gateway.addr,
        &guest_inbox,
        reqwest::Method::GET,
        "/api/apps/inbox/summary",
    )
    .await;
    assert_eq!(seen, 200, "{summary}");
    assert!(!summary.contains("agent_plan"), "{summary}");
    assert!(!summary.contains("capability-request:agent:"), "{summary}");
    let (answer, answer_body) = http_approve(&gateway.addr, &guest_inbox, ask.id.as_str()).await;
    assert_eq!(answer, 403, "{answer_body}");
    assert_eq!(answer_body, crate::agents::OWNER_NOT_ADMIN);
    assert!(!store
        .get_request(ask.id.as_str())
        .await
        .unwrap()
        .is_granted());
    let (stop, stop_body) = post_json(
        &gateway.addr,
        &owner.system_token,
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(stop, 403, "{stop_body}");
    assert!(stop_body.contains("admin passkey required"), "{stop_body}");
    let (other_seen, other_summary) = home_http(
        &gateway.addr,
        &super::app_token_for_authority(&home.data, "inbox", &other),
        reqwest::Method::GET,
        "/api/apps/inbox/summary",
    )
    .await;
    assert_eq!(other_seen, 200, "{other_summary}");
    assert!(!other_summary.contains(&pending_id), "{other_summary}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn another_admin_stops_an_agent_whose_owner_was_demoted_directly() {
    let home = Home::open();
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-plant-owner",
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-plant-other",
    );
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let context = passkey_context(&owner);
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data, &agent, HOST, &context,
    )
    .unwrap();
    let session =
        super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, &agent, &grant)
            .await
            .unwrap()
            .session_id;
    let demoted = crate::auth::demote_passkey_to_guest(
        &home.data,
        &owner.proof_binding_id,
        crate::auth::now_ts(),
    )
    .unwrap();
    crate::agents::notify_owner_demoted(&home.data, &demoted.principal_id);
    let mut stopped = false;
    for _ in 0..50 {
        if !capsule_live(&gateway.agent_url, &gateway.secret, &session).await {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(stopped, "a direct demote stops the guest");
    let mut signed = false;
    for _ in 0..50 {
        let present = crate::auth::load_auth_state(&home.data)
            .unwrap()
            .audit
            .into_iter()
            .any(|event| event.event_type == "agent.stopped");
        if present {
            signed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(signed, "a direct demote signs agent.stopped");
    let (signer, cause, capsule) = stop_cause(&home.data, &agent, "agent.stopped");
    assert_eq!(signer, other.principal_id);
    assert_eq!(cause, "owner demoted");
    assert_eq!(capsule, HOST);
    let (guest, guest_body) = post_json(
        &gateway.addr,
        &owner.system_token,
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(guest, 403, "{guest_body}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn the_last_passkey_revocation_stops_the_agent_and_one_of_two_does_not() {
    let home = Home::open();
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-revoke-owner",
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r11-revoke-other",
    );
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let context = passkey_context(&owner);
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data, &agent, HOST, &context,
    )
    .unwrap();
    let session =
        super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, &agent, &grant)
            .await
            .unwrap()
            .session_id;
    super::add_second_active_passkey(
        &home.data,
        &owner.principal_id,
        crate::auth::RuntimePrincipalRole::Admin,
    );
    let second = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .principals
        .into_iter()
        .find(|record| {
            record.principal_id == owner.principal_id
                && record.proof_binding_id != owner.proof_binding_id
        })
        .unwrap();
    let (kept, kept_body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/revoke", second.proof_binding_id),
    )
    .await;
    assert_eq!(kept, 200, "{kept_body}");
    assert!(capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    assert!(crate::agents::owner_is_admin_now(&home.data, &owner.principal_id).unwrap());
    let now = crate::auth::now_ts();
    let plan = super::super::gateway_inspect_actions::submit_pending_agent_plan(
        &home.data,
        &owner.principal_id,
        &agent,
        HOST,
        &session,
        &step_plan(),
        now,
    )
    .unwrap();
    let plan_id = plan["request_id"].as_str().unwrap();
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/revoke", owner.proof_binding_id),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    assert!(!crate::agents::owner_is_admin_now(&home.data, &owner.principal_id).unwrap());
    let stored = plan_file(&home.data, plan_id);
    assert_eq!(stored["status"], "passkey revoked", "{stored}");
    let (signer, cause, capsule) = stop_cause(&home.data, &agent, "agent.stopped");
    assert_eq!(signer, other.principal_id);
    assert_eq!(cause, "passkey revoked");
    assert_eq!(capsule, HOST);
    gateway.shutdown().await;
}

async fn http_deny(addr: &str, token: &str, request_id: &str) -> (u16, String) {
    let response = reqwest::Client::new()
        .post(format!("http://{addr}/api/apps/inbox/actions"))
        .header("host", addr)
        .header("origin", "null")
        .header("x-elastos-home-token", token)
        .header("content-type", "application/json")
        .body(
            json!({
                "action_id": format!("capability-deny-request:agent:{request_id}"),
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

#[tokio::test]
async fn an_audit_failure_on_a_sent_grant_names_the_next_start() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreiauditsent");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:audit-sent", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_kind(&home.data, "sent");
    let (status, body) = http_approve(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert_eq!(
        body,
        "Nothing ran. This approval is settled the next time Home starts."
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    let kinds: Vec<_> = grant_events(&home.data, &request_id)
        .into_iter()
        .map(|event| event.event_type)
        .collect();
    assert!(
        kinds.iter().any(|kind| kind == "agent.grant.approved"),
        "{kinds:?}"
    );
    assert!(
        !kinds.iter().any(|kind| kind == "agent.grant.sent"),
        "{kinds:?}"
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn an_audit_failure_on_a_denied_ask_names_the_retry() {
    let home = Home::open();
    let agent = home.create_agent("Notes", "bafkreiauditdeny");
    let gateway = Gateway::start(&home.data).await;
    let request_id = plant_pending(&home, "capsule:audit-deny", &agent).await;
    let token = inbox_token(&home.data, &home.owner, &home.proof);
    super::seams::arm_grant_fault(&home.data, false);
    let (status, body) = http_deny(&gateway.addr, &token, &request_id).await;
    assert_ne!(status, 200, "{body}");
    assert_eq!(body, "Nothing ran. Deny this ask again.");
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    gateway.shutdown().await;
}

fn live_home() -> (Home, PathBuf) {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    (home, dir)
}

#[tokio::test]
async fn a_failed_stop_row_on_disable_is_the_answer() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let _session = home.launch(&agent, &dir).await;
    super::super::gateway_agents::fail_next_agent_audit(&home.data);
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body.contains("the signed stop row was not recorded"),
        "{body}"
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_stop_row_on_retire_is_the_answer() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let _session = home.launch(&agent, &dir).await;
    super::super::gateway_agents::fail_next_agent_audit(&home.data);
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/retire",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body.contains("the signed stop row was not recorded"),
        "{body}"
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_stop_row_on_activate_false_is_the_answer() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let mut up = false;
    for _ in 0..50 {
        if capsule_live(&gateway.agent_url, &gateway.secret, &session).await {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(up, "guest is up before activate");
    super::super::gateway_agents::fail_next_agent_audit(&home.data);
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/activate",
        &json!({ "agent_id": agent, "active": false }).to_string(),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body.contains("the signed stop row was not recorded"),
        "{body}"
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_plan_close_on_disable_is_the_answer() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    super::super::gateway_inspect_actions::submit_pending_agent_plan(
        &home.data,
        &home.owner,
        &agent,
        HOST,
        "session:plan-close",
        &step_plan(),
        crate::auth::now_ts(),
    )
    .unwrap();
    super::seams::arm_grant_fault(&home.data, false);
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body.contains("the signed plan close was not recorded"),
        "{body}"
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn shutdown_signs_stopping_for_an_ended_session_with_an_inflight_effect() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).expect("plane");
    runtime.bind_plan_instance(&session, &agent);
    let book = runtime.plan_book();
    let _guard =
        crate::runtime::Runtime::try_enter_plan_effect(&book, &session, &agent, "hold-the-effect")
            .expect("the effect is in flight");
    runtime.end_planted_session_for_test(&session).await;
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let row = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .audit
        .into_iter()
        .find(|event| {
            event.event_type == "agent.stopped"
                && event.session_id.as_deref() == Some(session.as_str())
        })
        .expect("stopping row");
    assert_eq!(row.result, "stopping");
    assert_eq!(row.capsule_id.as_deref(), Some(HOST));
    gateway.shutdown().await;
}

#[tokio::test]
async fn retire_of_an_idle_agent_succeeds_while_the_plane_is_down() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Idle", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    stop_plane(&home.data).await;
    assert!(crate::api::agent_plane::plane_runtime(&home.data).is_none());
    std::fs::write(
        crate::runtime_control::home_runtime_coord_path(&home.data),
        br#"{"api_url":"http://127.0.0.1:9","attach_secret":"not-the-agent-plane"}"#,
    )
    .unwrap();
    let error =
        match super::super::gateway_home_runtime::stop_runtime_agent(&home.data, &agent).await {
            Err(error) => error,
            Ok(_) => panic!("a down plane still stopped the agent"),
        };
    assert_eq!(error.to_string(), "agent runtime is not running");
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/retire",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let record = crate::auth::stored_principal_record(&home.data, &agent)
        .unwrap()
        .unwrap();
    assert!(record.retired_at.is_some(), "{record:?}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_role_read_does_not_stop_another_admins_agent() {
    let home = Home::open();
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r12-read-owner",
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r12-read-other",
    );
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let context = passkey_context(&owner);
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data, &agent, HOST, &context,
    )
    .unwrap();
    let session =
        super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, &agent, &grant)
            .await
            .unwrap()
            .session_id;
    crate::agents::fail_owner_admin_read(&home.data);
    let (status, body) = post_json(
        &gateway.addr,
        &other.system_token,
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(
        body.contains("the owner's role could not be read"),
        "{body}"
    );
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    assert!(capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let stopped = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .audit
        .into_iter()
        .any(|event| event.event_type == "agent.stopped");
    assert!(!stopped, "a failed role read signed a stop");
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_demote_stop_is_signed_and_retried_at_the_next_start() {
    let home = Home::open();
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r12-stop-owner",
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        "r12-stop-other",
    );
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let context = passkey_context(&owner);
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data, &agent, HOST, &context,
    )
    .unwrap();
    let session =
        super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, &agent, &grant)
            .await
            .unwrap()
            .session_id;
    crate::api::agent_plane::arm_task_fault(&home.data, "the plane did not stop the agent");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert!(body.contains("did not stop"), "{body}");
    assert!(!body.contains(&home.data.display().to_string()), "{body}");
    // The parked ask is denied in the same failure, and that denial ends this
    // probe. The signed failed row is what the next start retries.
    let (signer, cause, capsule) = stop_cause(&home.data, &agent, "agent.stopped");
    assert_eq!(signer, other.principal_id);
    assert_eq!(cause, "owner demoted");
    assert_eq!(capsule, HOST);
    let failed = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .audit
        .into_iter()
        .find(|event| event.event_type == "agent.stopped")
        .unwrap();
    assert_eq!(failed.result, "failed");
    crate::api::agent_plane::clear_task_fault(&home.data);
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let retried = crate::auth::load_auth_state(&home.data)
        .unwrap()
        .audit
        .into_iter()
        .rfind(|event| event.event_type == "agent.stopped")
        .unwrap();
    assert_ne!(retried.result, "failed");
    gateway.shutdown().await;
}

static ROW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn audit_row(
    principal: &str,
    session: Option<&str>,
    event_type: &str,
    result: &str,
    reason: String,
) -> elastos_runtime::auth::RuntimeAuditEventV1 {
    elastos_runtime::auth::RuntimeAuditEventV1 {
        schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
        event_id: format!(
            "audit:r16:{event_type}:{}",
            ROW.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ),
        event_type: event_type.to_string(),
        principal_id: Some(principal.to_string()),
        proof_binding_id: None,
        session_id: session.map(str::to_string),
        challenge_id: None,
        capsule_id: None,
        result: result.to_string(),
        reason,
        occurred_at: crate::auth::now_ts(),
        signer_did: None,
        signature: None,
    }
}

/// A failed demote stop and an open `stopping` row, then 600 unrelated audit
/// rows push both out of the sign-in file's 512-row list. The agent file still
/// owes them: the retry runs once and the stopping row settles once.
#[tokio::test]
async fn owed_stops_outlive_a_full_audit_list() {
    let home = Home::open();
    let (owner, other) = admins(&home, "ring-wrap");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = launch_owned(&home, &owner, &agent).await;
    crate::api::agent_plane::arm_task_fault(&home.data, "the plane did not stop the agent");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    crate::api::agent_plane::clear_task_fault(&home.data);
    let reason = json!({ "agent_id": "agent-elsewhere" }).to_string();
    let stopping = audit_row(
        &owner.principal_id,
        Some("session-gone"),
        "agent.stopped",
        "stopping",
        reason,
    );
    crate::agent_record_audit::append_agent_row(&home.data, stopping).unwrap();
    for _ in 0..600 {
        let pad = audit_row(
            &owner.principal_id,
            None,
            "audit.pad",
            "ok",
            "pad".to_string(),
        );
        crate::auth::append_audit_event(&home.data, pad).unwrap();
    }
    assert!(
        stopped_rows(&home.data).is_empty(),
        "the pad did not wrap the list"
    );
    for _ in 0..2 {
        super::super::gateway_agents::confirm_stopping_rows(&home.data)
            .await
            .unwrap();
    }
    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
    let rows = stopped_rows(&home.data);
    let settled = |id: &str| rows.iter().filter(|row| row.reason.contains(id)).count();
    assert_eq!(
        settled(&agent),
        1,
        "the failed stop is retried once: {rows:?}"
    );
    assert_eq!(
        settled("agent-elsewhere"),
        1,
        "the stopping row settles once: {rows:?}"
    );
    assert!(rows.iter().all(|row| row.result == "ok"), "{rows:?}");
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
    gateway.shutdown().await;
}

/// Agents Off while the guest is in a call it does not leave, then a demote:
/// the stop reaches the guest on the retiring plane and is signed once.
#[tokio::test]
async fn a_demote_after_agents_off_stops_the_guest_on_the_retiring_plane() {
    let home = Home::open();
    let (owner, other) = admins(&home, "retiring-demote");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = launch_owned(&home, &owner, &agent).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    crate::api::agent_plane::plant_retiring_runtime(&home.data, Arc::clone(&runtime));
    std::fs::remove_file(crate::api::agent_plane::coords_path(&home.data)).unwrap();
    assert!(crate::api::agent_plane::live_coords(&home.data)
        .await
        .is_none());
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let info = runtime.get_capsule(&session).await;
    assert!(
        info.is_none_or(|info| info.ended_at.is_some()),
        "the guest still runs"
    );
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].result, "ok", "{rows:?}");
    gateway.shutdown().await;
}

/// A stop the plane answers 409 is a failed stop: signed `failed` and owed a
/// retry, not taken for "nothing to end".
#[tokio::test]
async fn a_409_stop_answer_is_signed_failed_and_owed() {
    let home = Home::open();
    let (owner, other) = admins(&home, "stop-409");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: "session-no-start".to_string(),
            name: "no start record".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: "session-no-start".to_string(),
            principal: Some(agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].result, "failed", "{rows:?}");
    let owed = crate::agents::owed_stop_rows(&home.data);
    assert!(owed.iter().any(|row| row.result == "failed"), "{owed:?}");
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    assert_eq!(
        stopped_rows(&home.data).len(),
        1,
        "a 409 retry is not signed ok"
    );
    runtime.unregister_capsule("session-no-start").await;
    gateway.shutdown().await;
}

/// A crash after the owed `stopping` row and before its signed row, then two
/// real gateway starts: the row is signed once and settles once as `ok`.
#[tokio::test]
async fn a_crash_between_the_owed_and_signed_stop_rows_settles_once_after_restart() {
    let home = Home::open();
    let (owner, _) = admins(&home, "crash-owed");
    let reason = json!({ "agent_id": "agent-crashed" }).to_string();
    let stopping = audit_row(
        &owner.principal_id,
        Some("session-crashed"),
        "agent.stopped",
        "stopping",
        reason,
    );
    crate::agents::note_stop_rows(&home.data, std::slice::from_ref(&stopping)).unwrap();
    assert!(stopped_rows(&home.data).is_empty());
    for _ in 0..2 {
        let gateway = Gateway::start(&home.data).await;
        gateway.shutdown().await;
    }
    let rows = stopped_rows(&home.data);
    let count = |result: &str| rows.iter().filter(|row| row.result == result).count();
    assert_eq!((count("stopping"), count("ok")), (1, 1), "{rows:?}");
    assert!(rows.iter().any(|row| row.event_id == stopping.event_id));
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
}

/// A crash after the signed `ok` settle and before its owed stop is cleared,
/// with the open `stopping` row already pushed out of the kept list: two real
/// starts leave that stop signed `ok` exactly once and owe nothing.
#[tokio::test]
async fn a_crash_after_the_signed_ok_settle_signs_the_stop_once_after_restart() {
    let home = Home::open();
    let (owner, _) = admins(&home, "crash-ok");
    let reason = json!({ "agent_id": "agent-settled" }).to_string();
    let stopping = audit_row(
        &owner.principal_id,
        Some("session-settled"),
        "agent.stopped",
        "stopping",
        reason,
    );
    crate::agent_record_audit::append_agent_row(&home.data, stopping).unwrap();
    for _ in 0..600 {
        let pad = audit_row(&owner.principal_id, None, "audit.pad", "ok", "pad".into());
        crate::auth::append_audit_event(&home.data, pad).unwrap();
    }
    assert!(stopped_rows(&home.data).is_empty(), "the pad did not wrap");
    super::seams::arm_grant_kind(&home.data, "after-signed-stop");
    let crashed = crate::agent_record_audit::confirm_stopping_rows(&home.data, |_| true);
    assert!(
        crashed.is_err(),
        "the crash between the two writes did not fire"
    );
    assert_eq!(
        stopped_rows(&home.data).len(),
        1,
        "the ok settle is signed before its owed stop is cleared"
    );
    for _ in 0..2 {
        let gateway = Gateway::start(&home.data).await;
        gateway.shutdown().await;
    }
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].result, "ok", "{rows:?}");
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
}

/// The owed `stopping` row was never signed. The `ok` stop is signed, then
/// the process dies before that owed row is cleared. Two real starts leave
/// exactly one `ok` and no later `stopping` row for that session.
#[tokio::test]
async fn a_restart_leaves_one_ok_and_no_stopping_row_after_a_landed_stop() {
    let home = Home::open();
    let (owner, _) = admins(&home, "landed-restart");
    let session = "session-landed-restart";
    let stopping = audit_row(
        &owner.principal_id,
        Some(session),
        "agent.stopped",
        "stopping",
        json!({ "agent_id": "agent-landed-restart" }).to_string(),
    );
    crate::agents::note_stop_rows(&home.data, std::slice::from_ref(&stopping)).unwrap();
    let ok = audit_row(
        &owner.principal_id,
        Some(session),
        "agent.stopped",
        "ok",
        json!({ "agent_id": "agent-landed-restart" }).to_string(),
    );
    super::seams::arm_grant_kind(&home.data, "after-signed-stop");
    let crashed = crate::agent_record_audit::append_agent_row(&home.data, ok);
    assert!(
        crashed.is_err(),
        "the crash after the signed ok did not fire"
    );
    let before = stopped_rows(&home.data);
    assert_eq!(before.len(), 1, "{before:?}");
    assert_eq!(before[0].result, "ok");
    for _ in 0..2 {
        let gateway = Gateway::start(&home.data).await;
        gateway.shutdown().await;
    }
    let rows = stopped_rows(&home.data);
    let for_session: Vec<_> = rows
        .iter()
        .filter(|row| row.session_id.as_deref() == Some(session))
        .collect();
    assert_eq!(for_session.len(), 1, "{rows:?}");
    assert_eq!(for_session[0].result, "ok", "{rows:?}");
    assert!(
        rows.iter().all(|row| row.result != "stopping"),
        "restart signed stopping after ok: {rows:?}"
    );
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
}

async fn register_live(home: &Home, session: &str, agent: &str) {
    crate::api::agent_plane::plane_runtime(&home.data)
        .expect("plane")
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: session.to_string(),
            name: "planted".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: session.to_string(),
            principal: Some(agent.to_string()),
            cause: None,
            ended_at: None,
        })
        .await;
}

/// A demotion committed while the owner's Inbox approval waits on its answer
/// gate: the approval reads the role again under the gate, is refused by
/// name, and signs no row and makes no grant.
#[tokio::test]
async fn a_demotion_while_the_approval_waits_on_its_gate_refuses_it_by_name() {
    let home = Home::open();
    let (owner, _) = admins(&home, "gate-demote");
    let agent = create_owned_agent(&home.data, &owner, "bafkreigatedemote");
    let gateway = Gateway::start(&home.data).await;
    register_live(&home, "capsule:gate-demote", &agent).await;
    let request_id = plant_pending(&home, "capsule:gate-demote", &agent).await;
    let token = inbox_token(&home.data, &owner.principal_id, &owner.proof_binding_id);
    let pause = super::seams::arm_answer_gate_pause(&home.data);
    let (addr, id) = (gateway.addr.clone(), request_id.clone());
    let approve = tokio::spawn(async move { http_approve(&addr, &token, &id).await });
    tokio::time::timeout(Duration::from_secs(15), pause.entered.notified())
        .await
        .expect("the approval did not reach its gate");
    let now = crate::auth::now_ts();
    crate::auth::demote_passkey_to_guest(&home.data, &owner.proof_binding_id, now).unwrap();
    pause.release.notify_one();
    let (status, body) = approve.await.unwrap();
    assert_ne!(status, 200, "{body}");
    assert!(body.contains(crate::agents::OWNER_NOT_ADMIN), "{body}");
    let rows = grant_audit(&home.data, &request_id);
    assert!(rows.is_empty(), "a refused approval signed {rows:?}");
    assert!(!usable_grant(&home.data, &request_id).await);
    gateway.shutdown().await;
}

/// A grant that reaches the plane for an agent whose owner is no longer an
/// admin is refused by name, and no grant is made.
#[tokio::test]
async fn the_plane_refuses_a_grant_when_the_owner_is_not_an_admin() {
    let home = Home::open();
    let (owner, _) = admins(&home, "plane-demote");
    let agent = create_owned_agent(&home.data, &owner, "bafkreiplanedemote");
    let gateway = Gateway::start(&home.data).await;
    register_live(&home, "capsule:plane-demote", &agent).await;
    let request_id = plant_pending(&home, "capsule:plane-demote", &agent).await;
    let now = crate::auth::now_ts();
    crate::auth::demote_passkey_to_guest(&home.data, &owner.proof_binding_id, now).unwrap();
    let shell = shell_token(&gateway.agent_url, &gateway.secret).await;
    let response = reqwest::Client::new()
        .post(format!("{}/api/capability/grant", gateway.agent_url))
        .header("authorization", format!("Bearer {shell}"))
        .json(&json!({"request_id": request_id, "duration": "session"}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    assert_eq!(status, 403, "{text}");
    assert_eq!(text, crate::agents::OWNER_NOT_ADMIN);
    assert!(!usable_grant(&home.data, &request_id).await);
    gateway.shutdown().await;
}

/// The demote route commits under the Inbox answer gate: while the gate is
/// held the owner stays an admin, and the demotion lands once it is free.
#[tokio::test]
async fn the_demote_route_commits_under_the_answer_gate() {
    let home = Home::open();
    let (owner, other) = admins(&home, "route-gate");
    let gateway = Gateway::start(&home.data).await;
    let held = super::super::grant_answer_gate().lock().await;
    let addr = gateway.addr.clone();
    let token = other.system_token.clone();
    let path = format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id);
    let demote =
        tokio::spawn(async move { home_http(&addr, &token, reqwest::Method::POST, &path).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        crate::agents::owner_is_admin_now(&home.data, &owner.principal_id).unwrap(),
        "the demotion committed while the answer gate was held"
    );
    drop(held);
    let (status, body) = demote.await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(!crate::agents::owner_is_admin_now(&home.data, &owner.principal_id).unwrap());
    gateway.shutdown().await;
}

/// Agents Off for an agent whose guest exits after the grant revoke, between
/// the stop's list of live rows and its read of them: the stop finds nothing
/// to end, and Off still signs that session stopped, once.
#[tokio::test]
async fn an_agent_that_exits_between_the_revoke_and_the_stop_is_signed_stopped_once() {
    let home = Home::open();
    let agent = home.create_agent("Exits", "bafkreiexits");
    let gateway = Gateway::start(&home.data).await;
    let token = system_token(&home);
    register_live(&home, "session-exits", &agent).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    let after_list = runtime.arm_stop_before_rows(&agent);
    let before_rows = runtime.arm_stop_before_rows(&agent);
    let addr = gateway.addr.clone();
    let body = json!({ "agent_id": agent, "active": false }).to_string();
    let off = tokio::spawn(async move {
        post_json(&addr, &token, "/api/apps/system/agents/activate", &body).await
    });
    tokio::time::timeout(Duration::from_secs(15), before_rows.entered.notified())
        .await
        .expect("the stop did not reach its mark");
    before_rows.release.notify_one();
    tokio::time::timeout(Duration::from_secs(15), after_list.entered.notified())
        .await
        .expect("the stop did not list the session");
    runtime.end_planted_session_for_test("session-exits").await;
    after_list.release.notify_one();
    let (status, body) = off.await.unwrap();
    assert_eq!(status, 200, "{body}");
    let rows: Vec<_> = stopped_rows(&home.data)
        .into_iter()
        .filter(|row| row.session_id.as_deref() == Some("session-exits"))
        .collect();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].result, "ok", "{rows:?}");
    gateway.shutdown().await;
}

/// A plane stop that names one session denies only that session's waiting
/// asks. Another live session of the same agent keeps its ask.
#[tokio::test]
async fn a_stop_for_one_session_leaves_another_sessions_ask_waiting() {
    let home = Home::open();
    let (owner, _) = admins(&home, "one-session");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let runtime = crate::api::agent_plane::plane_runtime(&home.data).unwrap();
    runtime
        .register_capsule(crate::runtime::RunningCapsuleInfo {
            id: "session-kept".to_string(),
            name: "kept".to_string(),
            status: crate::runtime::CAPSULE_RUNNING.to_string(),
            capsule_type: elastos_common::CapsuleType::Wasm,
            handle: None,
            session_id: "session-kept".to_string(),
            principal: Some(agent.clone()),
            cause: None,
            ended_at: None,
        })
        .await;
    let kept = plant_pending(&home, "session-kept", &agent).await;
    crate::api::agent_plane::plant_retiring_runtime(&home.data, Arc::clone(&runtime));
    let body = json!({ "agent_id": agent, "session_id": "session-other" }).to_string();
    let answer = crate::api::agent_plane::stop_on_retiring(&home.data, body.into_bytes()).await;
    assert!(answer.is_some_and(|answer| answer.status() != 200));
    let (store, _, _) = runtime.instance_authority_plane().unwrap();
    assert!(
        store.get_request(&kept).await.unwrap().is_pending(),
        "a stop for another session denied this ask"
    );
    let body = json!({ "agent_id": agent, "session_id": "session-kept" }).to_string();
    let _ = crate::api::agent_plane::stop_on_retiring(&home.data, body.into_bytes()).await;
    assert!(store.get_request(&kept).await.unwrap().is_denied());
    runtime.unregister_capsule("session-kept").await;
    gateway.shutdown().await;
}

fn stopped_rows(data: &Path) -> Vec<elastos_runtime::auth::RuntimeAuditEventV1> {
    crate::auth::load_auth_state(data)
        .unwrap()
        .audit
        .into_iter()
        .filter(|event| event.event_type == "agent.stopped")
        .collect()
}

fn admins(home: &Home, tag: &str) -> (super::TestPasskeyAuthority, super::TestPasskeyAuthority) {
    let owner = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Owner"),
        crate::auth::RuntimePrincipalRole::Admin,
        &format!("r15-{tag}-owner"),
    );
    let other = super::passkey_authority_with_name_role_credential(
        &home.data,
        Some("Other"),
        crate::auth::RuntimePrincipalRole::Admin,
        &format!("r15-{tag}-other"),
    );
    (owner, other)
}

async fn launch_owned(home: &Home, owner: &super::TestPasskeyAuthority, agent: &str) -> String {
    let dir = home._temp.path().join("probe");
    let grant = super::super::gateway_home_token::issue_home_agent_launch_token_with_context(
        &home.data,
        agent,
        HOST,
        &passkey_context(owner),
    )
    .unwrap();
    super::super::gateway_home_runtime::launch_runtime_agent(&home.data, &dir, agent, &grant)
        .await
        .unwrap()
        .session_id
}

/// Demote and revoke when the owner's agent has nothing to stop (idle, off,
/// retired, or agents off on this Home) answer 200 and sign no stop. A live
/// agent is stopped and its stop is signed once.
#[tokio::test]
async fn admin_loss_stops_only_a_live_agent_and_signs_it_once() {
    for state in ["idle", "off", "retired", "home off", "live"] {
        for route in ["demote-guest", "revoke"] {
            let home = Home::open();
            let (owner, other) = admins(&home, &format!("{state}-{route}").replace(' ', "-"));
            let dir = home._temp.path().join("probe");
            let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
            let gateway = Gateway::start(&home.data).await;
            let caller = crate::agents::Caller {
                principal_id: &owner.principal_id,
                proof_binding_id: &owner.proof_binding_id,
                session_id: &owner.session_id,
            };
            let mut session = None;
            match state {
                "off" => {
                    crate::agents::set_active(&home.data, &caller, &agent, false, 2).unwrap();
                }
                "retired" => {
                    crate::agents::retire(&home.data, &caller, &agent, 2).unwrap();
                }
                "home off" => {
                    let (status, body) = post_json(
                        &gateway.addr,
                        &system_token(&home),
                        "/api/apps/system/agents/disable",
                        "{}",
                    )
                    .await;
                    assert_eq!(status, 200, "{body}");
                }
                "live" => session = Some(launch_owned(&home, &owner, &agent).await),
                _ => {}
            }
            let (status, body) = home_http(
                &gateway.addr,
                &other.system_token,
                reqwest::Method::POST,
                &format!("/api/auth/passkeys/{}/{route}", owner.proof_binding_id),
            )
            .await;
            assert_eq!(status, 200, "{state} {route}: {body}");
            let rows = stopped_rows(&home.data);
            assert!(
                rows.iter().all(|row| row.result != "failed"),
                "{state} {route}: {rows:?}"
            );
            match session {
                Some(session) => {
                    assert_eq!(rows.len(), 1, "{state} {route}: {rows:?}");
                    assert!(!capsule_live(&gateway.agent_url, &gateway.secret, &session).await);
                }
                None => assert!(rows.is_empty(), "{state} {route}: {rows:?}"),
            }
            gateway.shutdown().await;
        }
    }
}

/// A self-revoke with an idle agent answers as before agents: 200, and the
/// cookie of the revoked passkey is cleared.
#[tokio::test]
async fn a_self_revoke_with_an_idle_agent_clears_the_cookie() {
    let home = Home::open();
    let (owner, _other) = admins(&home, "self-revoke");
    let dir = home._temp.path().join("probe");
    create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let response = reqwest::Client::new()
        .post(format!(
            "http://{}/api/auth/passkeys/{}/revoke",
            gateway.addr, owner.proof_binding_id
        ))
        .header("host", &gateway.addr)
        .header("origin", "null")
        .header("x-elastos-home-token", &owner.system_token)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let cleared = response.headers().contains_key(reqwest::header::SET_COOKIE);
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(cleared, "a self-revoke did not clear the cookie: {body}");
    assert!(stopped_rows(&home.data).is_empty());
    gateway.shutdown().await;
}

/// A failed demote stop, then the owner is an admin again and starts a new
/// run: the list load that retries failed stops leaves the new run alive.
#[tokio::test]
async fn a_failed_stop_is_not_retried_against_a_later_run() {
    let home = Home::open();
    let (owner, other) = admins(&home, "retry-new-run");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let first = launch_owned(&home, &owner, &agent).await;
    crate::api::agent_plane::arm_task_fault(&home.data, "the plane did not stop the agent");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    crate::api::agent_plane::clear_task_fault(&home.data);
    assert_eq!(stopped_rows(&home.data)[0].result, "failed");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!(
            "/api/auth/passkeys/{}/promote-admin",
            owner.proof_binding_id
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    for _ in 0..100 {
        if !capsule_live(&gateway.agent_url, &gateway.secret, &first).await {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let second = launch_owned(&home, &owner, &agent).await;
    crate::agent_record_audit::append_agent_row(
        &home.data,
        elastos_runtime::auth::RuntimeAuditEventV1 {
            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
            event_id: format!("audit:r15-start:{second}"),
            event_type: "agent.start.completed".to_string(),
            principal_id: Some(owner.principal_id.clone()),
            proof_binding_id: Some(owner.proof_binding_id.clone()),
            session_id: Some(second.clone()),
            challenge_id: None,
            capsule_id: Some(HOST.to_string()),
            result: "ok".to_string(),
            reason: json!({ "agent_id": agent }).to_string(),
            occurred_at: crate::auth::now_ts(),
            signer_did: None,
            signature: None,
        },
    )
    .unwrap();
    let (listed, list_body) = home_http(
        &gateway.addr,
        &owner.system_token,
        reqwest::Method::GET,
        "/api/apps/system/agents",
    )
    .await;
    assert_eq!(listed, 200, "{list_body}");
    assert!(
        capsule_live(&gateway.agent_url, &gateway.secret, &second).await,
        "the list load stopped the new run"
    );
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 1, "{rows:?}");
    gateway.shutdown().await;
}

/// A failed demote stop is not retried once the owner is an admin again.
#[tokio::test]
async fn a_failed_demote_stop_is_not_retried_after_the_owner_is_promoted() {
    let home = Home::open();
    let (owner, other) = admins(&home, "retry-promoted");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    launch_owned(&home, &owner, &agent).await;
    crate::api::agent_plane::arm_task_fault(&home.data, "the plane did not stop the agent");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    crate::api::agent_plane::clear_task_fault(&home.data);
    crate::auth::promote_passkey_to_admin(
        &home.data,
        &owner.proof_binding_id,
        crate::auth::now_ts(),
    )
    .unwrap();
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].result, "failed");
    gateway.shutdown().await;
}

/// Two list loads at once retry one failed stop once.
#[tokio::test]
async fn two_list_loads_retry_a_failed_stop_once() {
    let home = Home::open();
    let (owner, other) = admins(&home, "retry-twice");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    launch_owned(&home, &owner, &agent).await;
    crate::api::agent_plane::arm_task_fault(&home.data, "the plane did not stop the agent");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    crate::api::agent_plane::clear_task_fault(&home.data);
    let (first, second) = tokio::join!(
        super::super::gateway_agents::confirm_stopping_rows(&home.data),
        super::super::gateway_agents::confirm_stopping_rows(&home.data),
    );
    first.unwrap();
    second.unwrap();
    let rows = stopped_rows(&home.data);
    assert_eq!(rows.len(), 2, "one failed row and one retry: {rows:?}");
    assert_eq!(rows[0].result, "failed");
    assert_ne!(rows[1].result, "failed");
    gateway.shutdown().await;
}

fn ok_stops(data: &Path, session: &str) -> usize {
    stopped_rows(data)
        .iter()
        .filter(|event| event.result == "ok" && event.session_id.as_deref() == Some(session))
        .count()
}

async fn two_live_agents(home: &Home) -> (Gateway, String, String) {
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let first = home.create_agent("One", &cid);
    let second = home.create_agent("Two", &cid);
    let gateway = Gateway::start(&home.data).await;
    let one = home.launch(&first, &dir).await;
    let two = home.launch(&second, &dir).await;
    (gateway, one, two)
}

/// Sign fails on the first of two running agents. Both stops were owed before
/// the stop. The loop signs the other one. A retry of Agents Off signs the
/// one that failed, once.
#[tokio::test]
async fn a_failed_first_stop_signature_owes_both_and_signs_each_once() {
    let home = Home::open();
    let (gateway, one, two) = two_live_agents(&home).await;
    super::super::gateway_agents::fail_next_agent_audit(&home.data);
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_ne!(status, 200, "{body}");
    let owed = crate::agents::owed_stop_rows(&home.data);
    let owed_one = owed
        .iter()
        .any(|row| row.session_id.as_deref() == Some(one.as_str()));
    let owed_two = owed
        .iter()
        .any(|row| row.session_id.as_deref() == Some(two.as_str()));
    let signed = |session: &str| {
        stopped_rows(&home.data)
            .iter()
            .any(|row| row.session_id.as_deref() == Some(session))
    };
    assert!(
        (owed_one || signed(&one)) && (owed_two || signed(&two)),
        "a running session was neither owed nor signed: owed={owed:?}"
    );
    assert!(
        owed_one || owed_two,
        "the failed signature left nothing owed: {owed:?}"
    );
    assert!(
        signed(&one) || signed(&two),
        "Agents Off stopped at the first signature failure"
    );
    let (retry, retry_body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_eq!(retry, 200, "{retry_body}");
    assert_eq!(
        ok_stops(&home.data, &one),
        1,
        "session one was not signed once"
    );
    assert_eq!(
        ok_stops(&home.data, &two),
        1,
        "session two was not signed once"
    );
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
    let (again, again_body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_eq!(again, 200, "{again_body}");
    assert_eq!(
        ok_stops(&home.data, &one),
        1,
        "retry signed session one twice"
    );
    assert_eq!(
        ok_stops(&home.data, &two),
        1,
        "retry signed session two twice"
    );
    gateway.shutdown().await;
}

/// Both guests are stopped and the process dies before either stop is signed.
/// Restart signs each once.
#[tokio::test]
async fn a_crash_after_agents_off_stops_signs_both_once_on_restart() {
    let home = Home::open();
    let (gateway, one, two) = two_live_agents(&home).await;
    super::seams::arm_grant_kind(&home.data, "after-off-stop");
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/disable",
        "{}",
    )
    .await;
    assert_ne!(status, 200, "{body}");
    assert_eq!(ok_stops(&home.data, &one), 0);
    assert_eq!(ok_stops(&home.data, &two), 0);
    let owed = crate::agents::owed_stop_rows(&home.data);
    assert!(
        owed.iter()
            .any(|row| row.session_id.as_deref() == Some(one.as_str())),
        "the first stop was not owed: {owed:?}"
    );
    assert!(
        owed.iter()
            .any(|row| row.session_id.as_deref() == Some(two.as_str())),
        "the second stop was not owed: {owed:?}"
    );
    let owed_ids: Vec<String> = owed.iter().map(|row| row.event_id.clone()).collect();
    gateway.shutdown().await;
    // Agents are off, so the restarted gateway has no plane address.
    for _ in 0..2 {
        let mut restarted = Gateway::start(&home.data).await;
        let _ = restarted.stop.take().unwrap().send(());
        restarted.task.await.unwrap().unwrap();
    }
    assert_eq!(
        ok_stops(&home.data, &one),
        1,
        "restart signed session one twice or not at all"
    );
    assert_eq!(
        ok_stops(&home.data, &two),
        1,
        "restart signed session two twice or not at all"
    );
    let signed = stopped_rows(&home.data);
    for id in &owed_ids {
        assert_eq!(
            signed.iter().filter(|row| row.event_id == *id).count(),
            1,
            "owed stop {id} was not signed once: {signed:?}"
        );
    }
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
}

async fn restart_twice(data: &Path) {
    for _ in 0..2 {
        let mut restarted = Gateway::start(data).await;
        let _ = restarted.stop.take().unwrap().send(());
        restarted.task.await.unwrap().unwrap();
    }
}

fn one_owed_session(data: &Path, session: &str) -> String {
    let owed = crate::agents::owed_stop_rows(data);
    let ids: Vec<String> = owed
        .iter()
        .filter(|row| row.result == "stopping" && row.session_id.as_deref() == Some(session))
        .map(|row| row.event_id.clone())
        .collect();
    assert_eq!(ids.len(), 1, "the stop was not owed once: {owed:?}");
    assert_eq!(
        ok_stops(data, session),
        0,
        "a stop was signed before restart"
    );
    ids[0].clone()
}

fn assert_owed_settled_once(data: &Path, session: &str, owed_id: &str) {
    assert_eq!(
        ok_stops(data, session),
        1,
        "restart did not sign the stop once"
    );
    let signed = stopped_rows(data);
    assert_eq!(
        signed.iter().filter(|row| row.event_id == owed_id).count(),
        1,
        "the owed stop was not signed once: {signed:?}"
    );
    assert!(
        crate::agents::owed_stop_rows(data).is_empty(),
        "the owed stop was left open"
    );
}

async fn crash_one_stop(home: &Home, gateway: Gateway, session: &str, path: &str, body: &str) {
    super::seams::arm_grant_kind(&home.data, "after-stop");
    let (status, text) = post_json(&gateway.addr, &system_token(home), path, body).await;
    assert_ne!(status, 200, "{text}");
    assert!(text.contains("crash after the stop"), "{text}");
    let owed_id = one_owed_session(&home.data, session);
    gateway.shutdown().await;
    restart_twice(&home.data).await;
    assert_owed_settled_once(&home.data, session, &owed_id);
}

#[tokio::test]
async fn a_crash_after_owner_stop_signs_once_on_restart() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    crash_one_stop(
        &home,
        gateway,
        &session,
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
}

#[tokio::test]
async fn a_crash_after_activate_false_signs_once_on_restart() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    crash_one_stop(
        &home,
        gateway,
        &session,
        "/api/apps/system/agents/activate",
        &json!({ "agent_id": agent, "active": false }).to_string(),
    )
    .await;
}

#[tokio::test]
async fn a_crash_after_retire_signs_once_on_restart() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    crash_one_stop(
        &home,
        gateway,
        &session,
        "/api/apps/system/agents/retire",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
}

#[tokio::test]
async fn a_crash_after_admin_loss_signs_once_on_restart() {
    let home = Home::open();
    let (owner, other) = admins(&home, "crash-demote");
    let dir = home._temp.path().join("probe");
    let agent = create_owned_agent(&home.data, &owner, &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = launch_owned(&home, &owner, &agent).await;
    super::seams::arm_grant_kind(&home.data, "after-stop");
    let (status, body) = home_http(
        &gateway.addr,
        &other.system_token,
        reqwest::Method::POST,
        &format!("/api/auth/passkeys/{}/demote-guest", owner.proof_binding_id),
    )
    .await;
    assert_ne!(status, 200, "{body}");
    let owed_id = one_owed_session(&home.data, &session);
    gateway.shutdown().await;
    restart_twice(&home.data).await;
    assert_owed_settled_once(&home.data, &session, &owed_id);
}

#[tokio::test]
async fn a_crash_after_gateway_stop_signs_once_on_restart() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    super::seams::arm_grant_kind(&home.data, "after-stop");
    gateway.shutdown().await;
    let owed_id = one_owed_session(&home.data, &session);
    restart_twice(&home.data).await;
    assert_owed_settled_once(&home.data, &session, &owed_id);
}

#[tokio::test]
async fn a_crash_after_a_failed_stop_retry_signs_once_on_restart() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    let failed = audit_row(
        &home.owner,
        None,
        "agent.stopped",
        "failed",
        json!({ "agent_id": agent, "cause": "retry" }).to_string(),
    );
    crate::agent_record_audit::append_agent_row(&home.data, failed).unwrap();
    super::seams::arm_grant_kind(&home.data, "after-stop");
    super::super::gateway_agents::confirm_stopping_rows(&home.data)
        .await
        .unwrap();
    let owed_id = one_owed_session(&home.data, &session);
    gateway.shutdown().await;
    restart_twice(&home.data).await;
    assert_owed_settled_once(&home.data, &session, &owed_id);
}

#[tokio::test]
async fn a_panicked_runtime_signs_the_stop_and_stop_reports_it() {
    let (home, dir) = live_home();
    let agent = home.create_agent("Live", &sign_probe(&dir));
    let gateway = Gateway::start(&home.data).await;
    let session = home.launch(&agent, &dir).await;
    crate::api::agent_plane::plant_task_panic();
    let mut signed = false;
    for _ in 0..100 {
        signed = stopped_rows(&home.data)
            .iter()
            .any(|row| row.session_id.as_deref() == Some(session.as_str()));
        if signed {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(signed, "the panic path did not sign the stop");
    let before = stopped_rows(&home.data).len();
    let (status, body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let reply: Value = serde_json::from_str(&body).unwrap();
    let listed = reply["stopped"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(reply["stopping"].as_array().into_iter().flatten())
        .any(|row| row["session_id"] == session);
    assert!(listed, "stop did not report the ended session: {body}");
    let (again, again_body) = post_json(
        &gateway.addr,
        &system_token(&home),
        "/api/apps/system/agents/stop",
        &json!({ "agent_id": agent }).to_string(),
    )
    .await;
    assert_eq!(again, 200, "{again_body}");
    assert_eq!(
        stopped_rows(&home.data).len(),
        before,
        "stop signed a second row"
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn a_failed_note_after_the_signed_ok_does_not_append_again() {
    let home = Home::open();
    let (owner, _) = admins(&home, "note-ok");
    let reason = json!({ "agent_id": "agent-noted" }).to_string();
    let stopping = audit_row(
        &owner.principal_id,
        Some("session-noted"),
        "agent.stopped",
        "stopping",
        reason,
    );
    crate::agent_record_audit::append_agent_row(&home.data, stopping).unwrap();
    super::seams::arm_grant_kind(&home.data, "after-signed-stop");
    let crashed = crate::agent_record_audit::confirm_stopping_rows(&home.data, |_| true);
    assert!(
        crashed.is_err(),
        "the note after the signed ok did not fail"
    );
    let once = stopped_rows(&home.data)
        .iter()
        .filter(|row| row.result == "ok" && row.session_id.as_deref() == Some("session-noted"))
        .count();
    assert_eq!(once, 1, "the ok row was not signed");
    crate::agent_record_audit::confirm_stopping_rows(&home.data, |_| true).unwrap();
    let retry = stopped_rows(&home.data)
        .iter()
        .filter(|row| row.result == "ok" && row.session_id.as_deref() == Some("session-noted"))
        .count();
    assert_eq!(retry, 1, "the retry appended a second ok row");
    for _ in 0..600 {
        let pad = audit_row(&owner.principal_id, None, "audit.pad", "ok", "pad".into());
        crate::auth::append_audit_event(&home.data, pad).unwrap();
    }
    assert!(
        stopped_rows(&home.data)
            .iter()
            .all(|row| row.session_id.as_deref() != Some("session-noted")),
        "the pad did not roll the ok row off"
    );
    let marked = audit_row(
        &owner.principal_id,
        Some("session-rolled"),
        "agent.stopped",
        "stopping",
        json!({ "agent_id": "agent-rolled" }).to_string(),
    );
    crate::agent_record_audit::append_agent_row(&home.data, marked).unwrap();
    super::seams::arm_grant_kind(&home.data, "after-signed-stop");
    let rolled = crate::agent_record_audit::confirm_stopping_rows(&home.data, |_| true);
    assert!(rolled.is_err(), "the rolled note did not fail");
    for _ in 0..600 {
        let pad = audit_row(&owner.principal_id, None, "audit.pad", "ok", "pad".into());
        crate::auth::append_audit_event(&home.data, pad).unwrap();
    }
    assert!(
        stopped_rows(&home.data).is_empty(),
        "the second pad did not wrap"
    );
    crate::agent_record_audit::confirm_stopping_rows(&home.data, |_| true).unwrap();
    assert!(
        stopped_rows(&home.data).is_empty(),
        "a rolled-off ok was appended again"
    );
    assert!(crate::agents::owed_stop_rows(&home.data).is_empty());
}
