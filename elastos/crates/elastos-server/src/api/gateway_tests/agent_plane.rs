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
        let plane = crate::api::agent_plane::start(&self.data, None)
            .await
            .unwrap();
        let coords = wait_coords(&self.data).await;
        Plane {
            url: coords.api_url.clone(),
            secret: coords.attach_secret.clone(),
            plane,
        }
    }
}

struct Plane {
    url: String,
    secret: String,
    plane: crate::api::agent_plane::AgentPlane,
}

impl Plane {
    async fn token(&self) -> String {
        shell_token(&self.url, &self.secret).await
    }

    async fn shutdown(self) {
        let url = self.url.clone();
        self.plane.shutdown().await;
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
        let coords = wait_coords(data).await;
        Self {
            addr,
            agent_url: coords.api_url,
            secret: coords.attach_secret,
            task,
            stop: Some(stop_tx),
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
    let installed = crate::api::agent_plane::installed_provider_registry(&home.data)
        .expect("the plane kept the registry");
    assert!(Arc::ptr_eq(&registry, &installed));
    let response = installed
        .send_raw("model", &json!({ "op": "ping" }))
        .await
        .unwrap();
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
    let gateway = Gateway::start(&data).await;
    let coords = crate::api::agent_plane::live_coords(&data).await.unwrap();
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
        pending.contains("\"requests\":[]") || pending.contains("\"requests\": []"),
        "{pending}"
    );
    plane.shutdown().await;
    std::fs::write(
        home.data.join("capability-pending.json"),
        br#"{"requests":[{"request_id":"orphan","resource":"localhost://UsersAI/orphan/journal","action":"write"}]}"#,
    )
    .unwrap();
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
    assert!(!pending.contains("orphan"), "{pending}");
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
}

async fn host_panic_child() {
    let home = Home::open();
    let dir = home._temp.path().join("probe");
    let cid = sign_probe(&dir);
    let first = home.create_agent("Panic", &cid);
    let second = home.create_agent("Next", &cid);
    let gateway = Gateway::start(&home.data).await;
    crate::runtime::plant_host_panic();
    let session = home.launch(&first, &dir).await;
    let cause = poll_cause(&gateway, &session).await;
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
    let home_status = http_status(&format!("http://{}/healthz", gateway.addr)).await;
    println!(
        "MEASURE {}",
        json!({
            "kind": "task",
            "fault": fault,
            "launch": launch.err().map(|error| error.to_string()),
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
