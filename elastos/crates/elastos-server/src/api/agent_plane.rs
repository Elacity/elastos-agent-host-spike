//! The agent's Runtime in this process.
//!
//! The local gateway starts it on the Home data folder. It binds loopback,
//! keeps its own coordinates, and serves a stored-agent launch and stop.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::middleware::{from_fn, from_fn_with_state};
use axum::routing::{get, post};
use axum::{Extension, Router};

use crate::api::middleware::{auth_middleware, shell_only_middleware, ApiState};
use crate::api::server::ServerConfig;

const COORDS_FILE: &str = "agent-runtime-coords.json";
const KIND: &str = "agent";
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
    task: tokio::task::JoinHandle<()>,
    coords_path: PathBuf,
    data_dir: PathBuf,
}

impl AgentPlane {
    pub(crate) async fn shutdown(mut self) {
        self.task.abort();
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.task).await;
    }
}

impl Drop for AgentPlane {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.coords_path);
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

/// The routes a stored agent uses. A guest, app, or native start is not mounted.
pub(crate) fn router(config: ServerConfig) -> anyhow::Result<Router> {
    let runtime = config.runtime.clone();
    let session_registry = config.session_registry.clone();
    let data_dir = config.data_dir.clone();
    let attach_secret = config.attach_secret.clone();
    let audit_log = config.audit_log.clone();
    let api_state = ApiState {
        session_registry: session_registry.clone(),
    };
    let audit = audit_log.unwrap_or_else(|| {
        std::sync::Arc::new(elastos_runtime::primitives::audit::AuditLog::new())
    });
    let mut capsules = Router::new()
        .route("/api/capsules", get(crate::api::routes::list_capsules))
        .route("/api/capsules", post(crate::api::routes::launch_capsule));
    if crate::agents::build_allows() {
        capsules = capsules.route(
            "/api/capsules/stop-agent",
            post(crate::api::routes::stop_agent_session),
        );
    }
    let capsules = capsules
        .layer(from_fn(shell_only_middleware))
        .layer(from_fn_with_state(api_state, auth_middleware))
        .layer(Extension(data_dir))
        .layer(Extension(audit))
        .layer(Extension(runtime));
    let mut app = Router::new()
        .route("/api/health", get(crate::api::routes::health))
        .merge(capsules);
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
    Ok(app)
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
    runtime
        .set_provider_registry(registry, manager.clone(), pending.clone(), data_dir.clone())
        .await;
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
        drop(listener);
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
        };
        let mut task = tokio::spawn(async move {
            if let Err(error) = crate::api::server::start_server_with_sessions(config).await {
                tracing::info!(%error, "agent runtime stopped");
            }
        });
        let ready = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::select! {
                result = ready_rx => result.is_ok(),
                _ = &mut task => false,
            }
        })
        .await;
        if ready.ok() == Some(true) && health(&format!("http://{addr}")).await {
            let api_url = format!("http://{addr}");
            if let Err(error) = write_coords(&coords_path(&data_dir), &api_url, &attach_secret) {
                task.abort();
                let _ = task.await;
                return Err(error);
            }
            return Ok(AgentPlane {
                task,
                coords_path: coords_path(&data_dir),
                data_dir,
            });
        }
        task.abort();
        let _ = task.await;
        failure = Some(anyhow::anyhow!("agent runtime did not become ready"));
    }
    Err(failure.unwrap_or_else(|| anyhow::anyhow!("agent runtime did not bind")))
}

#[cfg(unix)]
fn write_coords(path: &Path, api_url: &str, attach_secret: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    crate::runtime_control::write_runtime_coords(
        path,
        &crate::runtime_control::RuntimeCoords {
            api_url: api_url.to_string(),
            attach_secret: attach_secret.to_string(),
            pid: std::process::id(),
            runtime_kind: KIND.to_string(),
            binary_sha256: String::new(),
            policy_sha256: String::new(),
            dependency_sha256: String::new(),
            generation: String::new(),
            home_url: String::new(),
        },
    )?;
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
    if !owner_only_file(&path) {
        return None;
    }
    let coords: crate::runtime_control::RuntimeCoords =
        serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
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
fn owner_only_file(path: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file()
        && !meta.file_type().is_symlink()
        && meta.permissions().mode() & 0o777 == 0o600
        && meta.uid() == unsafe { libc::getuid() }
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
