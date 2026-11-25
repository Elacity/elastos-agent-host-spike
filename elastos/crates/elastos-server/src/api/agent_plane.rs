//! The agent's Runtime in this process.
//!
//! The local gateway starts it on the Home data folder. It binds loopback,
//! keeps its own coordinates, and serves a stored-agent launch and stop.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use elastos_runtime::capability::{PendingRequestStore, Settler};
use elastos_runtime::primitives::audit::AuditLog;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{extract::State, Extension, Json, Router};
use elastos_runtime::session::Session;

use crate::api::middleware::{auth_middleware, shell_only_middleware, ApiState};
use crate::api::server::ServerConfig;

const COORDS_FILE: &str = "agent-runtime-coords.json";
/// What Home says when the agent Runtime's own task has ended.
pub(crate) const TASK_ENDED: &str = "agent runtime task ended";

static FAULTS: OnceLock<Mutex<HashMap<PathBuf, &'static str>>> = OnceLock::new();
#[cfg(test)]
static PLANT_TASK_PANIC: AtomicBool = AtomicBool::new(false);

fn faults() -> &'static Mutex<HashMap<PathBuf, &'static str>> {
    FAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The name Home gives when this data folder's agent Runtime task has ended.
pub(crate) fn task_fault(data_dir: &Path) -> Option<&'static str> {
    let Ok(map) = faults().lock() else {
        return Some(TASK_ENDED);
    };
    map.get(data_dir).copied()
}

#[cfg(unix)]
fn note_fault(data_dir: &Path, name: &'static str) {
    if let Ok(mut map) = faults().lock() {
        map.insert(data_dir.to_path_buf(), name);
    }
}

fn clear_fault(data_dir: &Path) {
    if let Ok(mut map) = faults().lock() {
        map.remove(data_dir);
    }
}

#[cfg(test)]
pub(crate) fn plant_task_panic() {
    PLANT_TASK_PANIC.store(true, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn dirs_lock_works() -> bool {
    dirs().lock().is_ok()
}

#[cfg(all(test, unix))]
static REGISTRIES: OnceLock<
    Mutex<HashMap<PathBuf, std::sync::Arc<elastos_runtime::provider::ProviderRegistry>>>,
> = OnceLock::new();

#[cfg(all(test, unix))]
fn registries(
) -> &'static Mutex<HashMap<PathBuf, std::sync::Arc<elastos_runtime::provider::ProviderRegistry>>> {
    REGISTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(all(test, unix))]
fn note_registry(
    data_dir: &Path,
    registry: std::sync::Arc<elastos_runtime::provider::ProviderRegistry>,
) {
    if let Ok(mut map) = registries().lock() {
        map.insert(data_dir.to_path_buf(), registry);
    }
}

#[cfg(all(test, unix))]
fn clear_registry(data_dir: &Path) {
    if let Ok(mut map) = registries().lock() {
        map.remove(data_dir);
    }
}

/// The provider registry this process installed for the agent Runtime.
#[cfg(all(test, unix))]
pub(crate) fn installed_provider_registry(
    data_dir: &Path,
) -> Option<std::sync::Arc<elastos_runtime::provider::ProviderRegistry>> {
    registries().lock().ok()?.get(data_dir).cloned()
}

#[cfg(unix)]
const KIND: &str = "agent";
#[cfg(unix)]
const RESERVED: &[&str] = &[
    "runtime-coords.json",
    "gateway-runtime-coords.json",
    "home-runtime-coords.json",
];

static DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

fn dirs() -> &'static Mutex<HashSet<PathBuf>> {
    DIRS.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Whether `data_dir` is the folder of the agent Runtime started in this process.
pub(crate) fn serves(data_dir: Option<&Path>) -> bool {
    data_dir.is_some_and(|dir| dirs().lock().map(|set| set.contains(dir)).unwrap_or(false))
}

pub(crate) fn coords_path(data_dir: &Path) -> PathBuf {
    data_dir.join(COORDS_FILE)
}

pub(crate) struct AgentPlane {
    server: tokio::task::AbortHandle,
    watcher: tokio::task::JoinHandle<()>,
    coords_path: PathBuf,
    data_dir: PathBuf,
    pub(crate) runtime: Arc<crate::runtime::Runtime>,
}

impl std::fmt::Debug for AgentPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentPlane")
            .field("coords_path", &self.coords_path)
            .field("data_dir", &self.data_dir)
            .finish_non_exhaustive()
    }
}

impl AgentPlane {
    /// Stop every live guest first, so each end revokes that guest's grants
    /// and closes its pending plans, then stop the listener.
    pub(crate) async fn shutdown(mut self) -> Vec<(String, String)> {
        let live: Vec<String> = self
            .runtime
            .list_capsules()
            .await
            .into_iter()
            .filter(|info| info.ended_at.is_none())
            .map(|info| info.id)
            .collect();
        let mut ended = Vec::new();
        for id in live {
            let agent_id = self
                .runtime
                .agent_session(&id)
                .await
                .map(|record| record.agent_id)
                .unwrap_or_default();
            ended.push((agent_id, id.clone()));
            let _ = self
                .runtime
                .stop_capsule_with_reason(&id, "agents off")
                .await;
        }
        self.server.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.watcher).await;
        ended
    }
}

impl Drop for AgentPlane {
    fn drop(&mut self) {
        self.server.abort();
        self.watcher.abort();
        let _ = std::fs::remove_file(&self.coords_path);
        clear_fault(&self.data_dir);
        #[cfg(all(test, unix))]
        clear_registry(&self.data_dir);
        if let Ok(mut set) = dirs().lock() {
            set.remove(&self.data_dir);
        }
    }
}

pub(crate) async fn live_coords(data_dir: &Path) -> Option<crate::runtime_control::RuntimeCoords> {
    #[cfg(unix)]
    {
        read_live(coords_path(data_dir)).await
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
        None
    }
}

/// Start the agent Runtime when this process already owns `data_dir`.
pub(crate) async fn start(
    data_dir: &Path,
    providers: Option<std::sync::Arc<elastos_runtime::provider::ProviderRegistry>>,
) -> anyhow::Result<AgentPlane> {
    if !crate::agents::build_allows() {
        anyhow::bail!(crate::agents::FEATURE_OFF);
    }
    #[cfg(unix)]
    {
        start_owned(data_dir.to_path_buf(), providers).await
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, providers);
        anyhow::bail!("agent runtime coordinates are owner-only");
    }
}

static PLANES: OnceLock<Mutex<HashMap<PathBuf, AgentPlane>>> = OnceLock::new();

fn planes() -> &'static Mutex<HashMap<PathBuf, AgentPlane>> {
    PLANES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Start the agent Runtime when the build and the owner both allow it, without
/// a second Home start. A process that does not own the data folder leaves the
/// record as it is: the owning Home is the one that binds the listener.
pub(crate) async fn ensure_running(
    data_dir: &Path,
    providers: Option<Arc<elastos_runtime::provider::ProviderRegistry>>,
) -> anyhow::Result<()> {
    if !crate::agents::build_allows()
        || !crate::agents::home_enabled(data_dir)
        || serves(Some(data_dir))
    {
        return Ok(());
    }
    let owner = crate::host_lock::active_host_process(data_dir)?;
    if owner.as_ref().map(|info| info.pid) != Some(std::process::id()) {
        return Ok(());
    }
    let plane = start(data_dir, providers).await?;
    if let Ok(mut held) = planes().lock() {
        held.insert(data_dir.to_path_buf(), plane);
    }
    Ok(())
}

/// End one agent's grants on this Home's agent Runtime and leave the guest
/// running. A Home whose plane is not in this process has nothing to revoke.
pub(crate) async fn revoke_agent_grants(data_dir: &Path, agent_id: &str) {
    let runtime = planes().lock().ok().and_then(|held| {
        held.get(data_dir)
            .map(|plane| std::sync::Arc::clone(&plane.runtime))
    });
    if let Some(runtime) = runtime {
        runtime
            .revoke_live_agent_grants(agent_id, "agent off")
            .await;
    }
}

/// Stop the agent Runtime for this Home. Live guests end first, inside
/// [`AgentPlane::shutdown`], so their grants and pending plans end with them.
pub(crate) async fn stop_running(data_dir: &Path) -> Vec<(String, String)> {
    let plane = planes()
        .lock()
        .ok()
        .and_then(|mut held| held.remove(data_dir));
    if let Some(plane) = plane {
        let dir = plane.data_dir.clone();
        let ended = plane.shutdown().await;
        let _ = crate::api::gateway::close_home_plans(&dir, "agents off");
        crate::resource_bridge::notify_plan_waiters();
        return ended;
    }
    Vec::new()
}

/// A grant whose asker has no live capsule is refused. The shell session is
/// not the asker; the pending request names the guest.
async fn grant_if_asker_is_live(
    State(state): State<crate::api::handlers::CapabilityState>,
    Extension(session): Extension<Session>,
    Extension(runtime): Extension<Arc<crate::runtime::Runtime>>,
    Extension(data_dir): Extension<Option<PathBuf>>,
    Json(input): Json<crate::api::handlers::GrantRequestInput>,
) -> Response {
    if let Some(request) = state.pending_store.get_request(&input.request_id).await {
        let live = runtime
            .get_capsule(request.session_id.as_str())
            .await
            .is_some_and(|info| info.ended_at.is_none());
        if !live {
            return (StatusCode::CONFLICT, "the asking session has ended").into_response();
        }
        if let Some(dir) = data_dir.as_deref() {
            if let Some(record) = runtime.agent_session(request.session_id.as_str()).await {
                if let Err(error) = crate::agents::refuse_inactive_agent(dir, &record.agent_id) {
                    return (StatusCode::CONFLICT, error.to_string()).into_response();
                }
            }
        }
    }
    match crate::api::handlers::grant_request(State(state), Extension(session), Json(input)).await {
        Ok(body) => body.into_response(),
        Err((status, text)) => (status, text).into_response(),
    }
}

/// The routes a stored agent uses. A guest, app, or native start is not mounted.
pub(crate) fn router(config: ServerConfig) -> anyhow::Result<Router> {
    let runtime = config.runtime.clone();
    let session_registry = config.session_registry.clone();
    let data_dir = config.data_dir.clone();
    let attach_secret = config.attach_secret.clone();
    let audit_log = config.audit_log.clone();
    let pending = config.pending_store.clone();
    let api_state = ApiState {
        session_registry: session_registry.clone(),
    };
    let audit = audit_log.unwrap_or_else(|| {
        std::sync::Arc::new(elastos_runtime::primitives::audit::AuditLog::new())
    });
    let capability_state = crate::api::handlers::CapabilityState {
        pending_store: pending.clone(),
        capability_manager: config.capability_manager.clone(),
        capability_store: config.capability_store.clone(),
        policy_evaluator: std::sync::Arc::new(elastos_runtime::capability::PolicyEvaluator::new(
            Box::new(elastos_runtime::capability::evaluator::ShellPassthroughVerifier),
            config.capability_manager.audit_log().clone(),
        )),
        agent_home: data_dir.clone(),
    };
    let mut capsules = Router::new()
        .route("/api/capsules", get(crate::api::routes::list_capsules))
        .route("/api/capsules", post(crate::api::routes::launch_capsule));
    if crate::agents::build_allows() {
        capsules = capsules.route("/api/capsules/stop-agent", post(stop_and_settle));
    }
    let capsules = capsules
        .layer(from_fn(shell_only_middleware))
        .layer(from_fn_with_state(api_state.clone(), auth_middleware))
        .layer(Extension(data_dir.clone()))
        .layer(Extension(audit))
        .layer(Extension(pending))
        .layer(Extension(runtime.clone()));
    let asks = Router::new()
        .route("/api/capability/pending", get(list_owner_pending))
        .route("/api/capability/grant", post(grant_if_asker_is_live))
        .route(
            "/api/capability/deny",
            post(crate::api::handlers::deny_request),
        )
        .layer(Extension(data_dir.clone()))
        .layer(Extension(runtime))
        .layer(from_fn(attach_shell_only))
        .layer(from_fn_with_state(api_state, auth_middleware))
        .with_state(capability_state);
    let mut app = Router::new()
        .route("/api/health", get(crate::api::routes::health))
        .merge(capsules)
        .merge(asks);
    if let Some(secret) = attach_secret {
        app = app.merge(
            Router::new()
                .route(
                    "/api/auth/attach",
                    post(crate::api::handlers::attach::attach),
                )
                .with_state(crate::api::handlers::attach::AttachState {
                    session_registry,
                    secret,
                }),
        );
    }
    #[cfg(test)]
    {
        app = app.route("/api/test/plane-route-panic", get(planted_route_panic));
    }
    Ok(app)
}

#[cfg(test)]
async fn planted_route_panic() -> &'static str {
    panic!("planted agent route panic")
}

/// The attach-secret shell, with no VM. A guest and a Home app session are named and refused.
pub(crate) fn shell_refusal(session: &Session) -> Option<&'static str> {
    if session.is_shell() && session.vm_id.is_none() {
        return None;
    }
    if !session.is_shell() && session.vm_id.is_some() {
        return Some("a guest session is refused");
    }
    Some("a Home app session is refused")
}

async fn attach_shell_only(req: Request<Body>, next: Next) -> Response {
    match req.extensions().get::<Session>().map(shell_refusal) {
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Session not found in request extensions",
        )
            .into_response(),
        Some(Some(reason)) => (StatusCode::FORBIDDEN, reason).into_response(),
        Some(None) => next.run(req).await,
    }
}

async fn list_owner_pending(
    axum::extract::State(state): axum::extract::State<crate::api::handlers::CapabilityState>,
    Extension(runtime): Extension<Arc<crate::runtime::Runtime>>,
    Extension(_session): Extension<Session>,
) -> Json<serde_json::Value> {
    let mut requests = Vec::new();
    for ask in state.pending_store.list_pending().await {
        let session_id = ask.session_id.to_string();
        let agent_id = runtime
            .agent_session(&session_id)
            .await
            .map(|row| row.agent_id)
            .unwrap_or_default();
        requests.push(serde_json::json!({
            "request_id": ask.id.to_string(), "session_id": session_id, "agent_id": agent_id,
            "resource": ask.resource.to_string(), "action": ask.action.to_string(),
            "reason": ask.reason, "requested_at": ask.requested_at.unix_secs,
            "expires_at": ask.expires_at.unix_secs,
        }));
    }
    Json(serde_json::json!({ "requests": requests }))
}

#[derive(serde::Deserialize)]
struct PlaneStopBody {
    agent_id: String,
}

async fn stop_and_settle(
    Extension(runtime): Extension<Arc<crate::runtime::Runtime>>,
    Extension(audit): Extension<Arc<AuditLog>>,
    Extension(pending): Extension<Arc<PendingRequestStore>>,
    body: axum::body::Bytes,
) -> Response {
    // The same fields Stop accepts. A body Stop will refuse does not deny
    // the waiting asks.
    if let Ok(request) = serde_json::from_slice::<PlaneStopBody>(&body) {
        let agent_id = request.agent_id.trim();
        if !agent_id.is_empty() {
            let ids = runtime.live_sessions_for_agent(agent_id).await;
            deny_waiting_asks(&pending, &ids, agent_id).await;
        }
    }
    crate::api::routes::stop_agent_session(Extension(runtime), Extension(audit), body).await
}

/// Deny every still-waiting ask of these sessions. The reason names the agent.
pub(crate) async fn deny_waiting_asks(
    store: &PendingRequestStore,
    session_ids: &[String],
    agent_id: &str,
) {
    let reason = format!("denied: {agent_id} stopped");
    for ask in store.list_pending().await {
        if session_ids
            .iter()
            .any(|id| id == &ask.session_id.to_string())
        {
            let _ = store
                .deny_request_by(ask.id.as_str(), &reason, Settler::Runtime)
                .await;
        }
    }
}

/// A crashed write leaves `.{coords}.{nonce}.tmp` beside the coordinates,
/// and that file holds the attach secret. Start removes those siblings
/// before it writes a new file.
#[cfg(unix)]
fn sweep_coord_temps(data_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(data_dir) else {
        return;
    };
    let prefix = format!(".{COORDS_FILE}.");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
async fn start_owned(
    data_dir: PathBuf,
    providers: Option<std::sync::Arc<elastos_runtime::provider::ProviderRegistry>>,
) -> anyhow::Result<AgentPlane> {
    let owner = crate::host_lock::active_host_process(&data_dir)?;
    if owner.as_ref().map(|info| info.pid) != Some(std::process::id()) {
        anyhow::bail!("agent runtime starts for the owner of this data folder");
    }
    sweep_coord_temps(&data_dir);
    let path = coords_path(&data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!("agent coordinates path is a symlink");
        }
        Ok(meta) if meta.is_file() => std::fs::remove_file(&path)?,
        Ok(_) => anyhow::bail!("agent coordinates path is not a file"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if RESERVED.contains(&COORDS_FILE) {
        anyhow::bail!("agent coordinates use their own file");
    }
    if !crate::agents::home_enabled(&data_dir) {
        anyhow::bail!(crate::agents::NOT_ENABLED);
    }
    dirs()
        .lock()
        .expect("agent plane set")
        .insert(data_dir.clone());
    let started = listen(data_dir.clone(), providers).await;
    if started.is_err() {
        if let Ok(mut set) = dirs().lock() {
            set.remove(&data_dir);
        }
    }
    started
}

#[cfg(unix)]
async fn listen(
    data_dir: PathBuf,
    providers: Option<std::sync::Arc<elastos_runtime::provider::ProviderRegistry>>,
) -> anyhow::Result<AgentPlane> {
    let (loaded, _) = elastos_runtime::bootstrap::RuntimeConfig::load(&data_dir);
    let storage = std::sync::Arc::new(
        elastos_storage::providers::LocalFSProvider::new(data_dir.join("agent-runtime-storage"))
            .await?,
    );
    let runtime = std::sync::Arc::new(crate::runtime::Runtime::with_providers_and_component(
        storage,
        Vec::new(),
        Some(std::sync::Arc::new(
            elastos_compute::providers::ComponentProvider::new(),
        )),
    ));
    runtime
        .configure_capsule_admission(&data_dir, &loaded.trusted_keys, loaded.dev_mode)
        .await?;
    let audit = std::sync::Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let sessions = std::sync::Arc::new(elastos_runtime::session::SessionRegistry::new(
        audit.clone(),
    ));
    let store = std::sync::Arc::new(elastos_runtime::capability::CapabilityStore::new());
    let manager = std::sync::Arc::new(elastos_runtime::capability::CapabilityManager::new(
        store.clone(),
        audit.clone(),
        std::sync::Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new()),
    ));
    let pending = std::sync::Arc::new(elastos_runtime::capability::PendingRequestStore::new(
        audit.clone(),
    ));
    let registry = providers
        .unwrap_or_else(|| std::sync::Arc::new(elastos_runtime::provider::ProviderRegistry::new()));
    #[cfg(test)]
    let installed = registry.clone();
    runtime
        .set_provider_registry(registry, manager.clone(), pending.clone(), data_dir.clone())
        .await;
    runtime.keep_revocations_in_memory();
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable: {error}"))?;
    let attach_secret = hex::encode(secret);
    let mut failure = None;
    for _ in 0..4 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        if address.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
            anyhow::bail!("agent runtime bind is not loopback");
        }
        let addr = format!("127.0.0.1:{}", address.port());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let config = ServerConfig {
            runtime: runtime.clone(),
            session_registry: sessions.clone(),
            capability_manager: manager.clone(),
            capability_store: store.clone(),
            pending_store: pending.clone(),
            namespace_store: None,
            provider_registry: None,
            audit_log: Some(audit.clone()),
            identity_state: None,
            docs_dir: None,
            addr: addr.clone(),
            capsule_dir: None,
            data_dir: Some(data_dir.clone()),
            tls_config: None,
            supervisor: None,
            ready_tx: Some(ready_tx),
            attach_secret: Some(attach_secret.clone()),
            host_helpers: Vec::new(),
            agents_only: true,
            listener: Some(listener),
        };
        let mut running = spawn_agent_server(config, data_dir.clone());
        let ready = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = ready_rx => result.is_ok(),
                _ = &mut running.watcher => false,
            }
        })
        .await;
        if ready.ok() == Some(true) && health(&format!("http://{addr}")).await {
            let api_url = format!("http://{addr}");
            if let Err(error) = write_coords(&coords_path(&data_dir), &api_url, &attach_secret) {
                running.stop().await;
                return Err(error);
            }
            clear_fault(&data_dir);
            #[cfg(test)]
            note_registry(&data_dir, installed.clone());
            let _ = crate::api::gateway::reconcile_lost_plan_receipts(&data_dir);
            return Ok(AgentPlane {
                server: running.server,
                watcher: running.watcher,
                coords_path: coords_path(&data_dir),
                data_dir,
                runtime,
            });
        }
        running.stop().await;
        failure = Some(anyhow::anyhow!("agent runtime did not become ready"));
    }
    Err(failure.unwrap_or_else(|| anyhow::anyhow!("agent runtime did not bind")))
}

#[cfg(unix)]
struct RunningServer {
    server: tokio::task::AbortHandle,
    watcher: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl RunningServer {
    async fn stop(self) {
        self.server.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), self.watcher).await;
    }
}

#[cfg(unix)]
fn spawn_agent_server(config: ServerConfig, data_dir: PathBuf) -> RunningServer {
    let server = tokio::spawn(async move {
        let serve = crate::api::server::start_server_with_sessions(config);
        #[cfg(test)]
        {
            tokio::pin!(serve);
            loop {
                tokio::select! {
                    biased;
                    result = &mut serve => {
                        if let Err(error) = result {
                            tracing::info!(%error, "agent runtime stopped");
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(20)) => {
                        if PLANT_TASK_PANIC.swap(false, Ordering::AcqRel) {
                            panic!("planted agent runtime task panic");
                        }
                    }
                }
            }
        }
        #[cfg(not(test))]
        if let Err(error) = serve.await {
            tracing::info!(%error, "agent runtime stopped");
        }
    });
    let abort = server.abort_handle();
    let watcher = tokio::spawn(async move {
        if let Err(error) = server.await {
            if error.is_panic() {
                note_fault(&data_dir, TASK_ENDED);
            }
        }
    });
    RunningServer {
        server: abort,
        watcher,
    }
}

#[cfg(unix)]
fn write_coords(path: &Path, api_url: &str, attach_secret: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("agent coordinates path has no parent"))?;
    let parent_meta = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        parent_meta.is_dir() && !parent_meta.file_type().is_symlink(),
        "agent coordinates parent must be a real directory"
    );
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| anyhow::anyhow!("OS randomness unavailable: {error}"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("agent coordinates filename is invalid"))?;
    let temporary = parent.join(format!(".{file_name}.{}.tmp", hex::encode(nonce)));
    let data = serde_json::to_vec_pretty(&crate::runtime_control::RuntimeCoords {
        api_url: api_url.to_string(),
        attach_secret: attach_secret.to_string(),
        pid: std::process::id(),
        runtime_kind: KIND.to_string(),
        binary_sha256: String::new(),
        policy_sha256: String::new(),
        dependency_sha256: String::new(),
        generation: String::new(),
        process_start: String::new(),
        home_url: String::new(),
    })?;
    let write_result = (|| -> anyhow::Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW);
        let mut file = options.open(&temporary)?;
        file.write_all(&data)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    write_result?;
    let meta = std::fs::symlink_metadata(path)?;
    let owner_only = !meta.file_type().is_symlink()
        && meta.permissions().mode() & 0o777 == 0o600
        && meta.uid() == unsafe { libc::getuid() };
    if !owner_only {
        let _ = std::fs::remove_file(path);
        anyhow::bail!("agent coordinates are not owner-only");
    }
    Ok(())
}

#[cfg(unix)]
async fn read_live(path: PathBuf) -> Option<crate::runtime_control::RuntimeCoords> {
    let coords: crate::runtime_control::RuntimeCoords =
        serde_json::from_slice(&read_owner_only(&path)?).ok()?;
    if coords.runtime_kind != KIND
        || coords.pid != std::process::id()
        || !coords.api_url.starts_with("http://127.0.0.1:")
        || crate::local_http::LoopbackHttpBaseUrl::parse(&coords.api_url).is_err()
    {
        return None;
    }
    health(&coords.api_url).await.then_some(coords)
}

#[cfg(unix)]
fn read_owner_only(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut options = std::fs::OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.mode() & 0o777 != 0o600
        || meta.uid() != unsafe { libc::getuid() }
    {
        return None;
    }
    let mut data = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut data).ok()?;
    if data.len() > 64 * 1024 {
        return None;
    }
    Some(data)
}

#[cfg(unix)]
async fn health(url: &str) -> bool {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    for _ in 0..50 {
        if client
            .get(format!("{url}/api/health"))
            .send()
            .await
            .ok()
            .is_some_and(|response| response.status().is_success())
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[cfg(test)]
mod tests {
    use elastos_runtime::capability::{
        Action, PendingRequestStore, RequestStatus, ResourceId, Settler,
    };
    use elastos_runtime::primitives::audit::AuditLog;
    use elastos_runtime::session::{Session, SessionId, SessionType};
    use std::sync::Arc;

    #[cfg(unix)]
    #[test]
    fn start_sweeps_a_planted_coordinates_temp_that_holds_a_secret() {
        let dir = tempfile::tempdir().expect("temp dir");
        let planted = dir
            .path()
            .join(format!(".{}.deadbeef.tmp", super::COORDS_FILE));
        std::fs::write(&planted, b"attach-secret-plant").unwrap();
        assert!(planted.is_file());
        super::sweep_coord_temps(dir.path());
        assert!(!planted.exists(), "start removes the planted secret file");
    }

    #[test]
    fn the_plane_helpers_start_disarmed_and_a_fresh_folder_has_no_registry() {
        assert!(super::dirs_lock_works());
        #[cfg(unix)]
        {
            let dir = tempfile::tempdir().expect("temp dir");
            assert!(super::installed_provider_registry(dir.path()).is_none());
        }
        assert!(!super::PLANT_TASK_PANIC.load(std::sync::atomic::Ordering::Acquire));
        // The planter stays uncalled. Calling it here would arm a listener
        // that shares this process. A default test build still names it.
        fn not_the_planter() {}
        assert!(!std::ptr::fn_addr_eq(
            super::plant_task_panic as fn(),
            not_the_planter as fn()
        ));
    }

    #[test]
    fn only_the_unbound_attach_shell_may_answer() {
        assert!(super::shell_refusal(&Session::new(SessionType::Shell, None)).is_none());
        assert_eq!(
            super::shell_refusal(&Session::new(SessionType::Shell, Some("vm".into()))),
            Some("a Home app session is refused")
        );
        assert_eq!(
            super::shell_refusal(&Session::new(SessionType::Capsule, Some("guest-vm".into()))),
            Some("a guest session is refused")
        );
        assert_eq!(
            super::shell_refusal(&Session::new(SessionType::Capsule, None)),
            Some("a Home app session is refused")
        );
    }

    #[tokio::test]
    async fn stop_denies_that_agents_ask_and_leaves_the_other() {
        let store = PendingRequestStore::new(Arc::new(AuditLog::new()));
        let kept = store
            .create_request(
                SessionId::from_string("session-b"),
                ResourceId::new("localhost://UsersAI/b/journal"),
                Action::Write,
            )
            .await;
        let denied = store
            .create_request(
                SessionId::from_string("session-a"),
                ResourceId::new("localhost://UsersAI/a/journal"),
                Action::Read,
            )
            .await;
        super::deny_waiting_asks(&store, &["session-a".to_string()], "agent-a").await;
        match store.get_request(denied.id.as_str()).await.unwrap().status {
            RequestStatus::Denied { reason, settled_by } => {
                assert!(reason.contains("agent-a"), "{reason}");
                assert_eq!(settled_by, Settler::Runtime);
            }
            other => panic!("ask stayed {other:?}"),
        }
        assert!(store
            .get_request(kept.id.as_str())
            .await
            .unwrap()
            .is_pending());
    }

    #[tokio::test]
    async fn a_second_ask_is_accepted_while_the_first_is_pending() {
        let store = PendingRequestStore::new(Arc::new(AuditLog::new()));
        let session = SessionId::from_string("session-a");
        let resource = ResourceId::new("localhost://UsersAI/a/journal");
        let first = store
            .create_request(session.clone(), resource.clone(), Action::Write)
            .await;
        let second = store.create_request(session, resource, Action::Write).await;
        assert!(first.is_pending() && second.is_pending());
        assert_ne!(first.id.as_str(), second.id.as_str());
        assert_eq!(store.list_pending().await.len(), 2);
    }
}
