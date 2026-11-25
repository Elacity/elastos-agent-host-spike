use elastos_server::binaries::{checked_native_provider, checked_native_provider_with_data_dir};
#[cfg(all(test, unix))]
use std::fs;
#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use elastos_common::localhost::{ensure_file_backed_roots, file_backed_prefixes};
use elastos_runtime::provider::{
    ProviderInvocation, ProviderInvocationTransport, ProviderTransfer,
};
use elastos_runtime::{capability, content, namespace, primitives, provider, session};
use elastos_server::api::browser_engine_protocol::{
    BROWSER_ENGINE_PROTOCOL_VERSION, BROWSER_ENGINE_PROVIDER_ID,
};
use elastos_server::binaries;
use elastos_server::carrier::configured_carrier_bind_addr;
use elastos_server::content::ContentProvider;
use elastos_server::documents::DocumentsProvider;
use elastos_server::sources::{default_data_dir, local_session_owner};
use elastos_server::{api, fetcher, ownership};
use elastos_wallet_contract::WALLET_PROTOCOL_VERSION;

pub(crate) struct ServerInfrastructure {
    pub(crate) audit_log: Arc<primitives::audit::AuditLog>,
    pub(crate) session_registry: Arc<session::SessionRegistry>,
    pub(crate) capability_manager: Arc<capability::CapabilityManager>,
    pub(crate) capability_store: Arc<capability::CapabilityStore>,
    pub(crate) pending_store: Arc<capability::pending::PendingRequestStore>,
    pub(crate) provider_registry: Arc<provider::ProviderRegistry>,
    pub(crate) namespace_store: Arc<namespace::NamespaceStore>,
    pub(crate) identity_state: Option<api::handlers::identity::IdentityState>,
    pub(crate) tls_config: Option<axum_server::tls_rustls::RustlsConfig>,
    pub(crate) provider_cid: String,
    pub(crate) shell_cid: Option<String>,
    pub(crate) host_helpers: Vec<api::server::HostHelperProcess>,
    pub(crate) carrier_service: Option<elastos_server::carrier::CarrierRuntimeService>,
    pub(crate) collaboration_context: api::gateway::GatewayCollaborationContext,
    pub(crate) collaboration_service:
        Option<elastos_server::collaboration_startup::CollaborationRuntimeService>,
}

const CONTENT_REPAIR_SCHEDULER_ENV: &str = "ELASTOS_CONTENT_REPAIR_SCHEDULER";
const CONTENT_REPAIR_SCHEDULER_INTERVAL_ENV: &str = "ELASTOS_CONTENT_REPAIR_INTERVAL_SECS";
const CONTENT_REPAIR_SCHEDULER_LIMIT_ENV: &str = "ELASTOS_CONTENT_REPAIR_LIMIT";
const CONTENT_REPAIR_SCHEDULER_MAX_ATTEMPTS_ENV: &str = "ELASTOS_CONTENT_REPAIR_MAX_ATTEMPTS";
const CONTENT_REPAIR_SCHEDULER_FAILURE_BUDGET_ENV: &str = "ELASTOS_CONTENT_REPAIR_FAILURE_BUDGET";
const CONTENT_REPAIR_SCHEDULER_INCLUDE_HEALTHY_ENV: &str = "ELASTOS_CONTENT_REPAIR_INCLUDE_HEALTHY";
const CONTENT_REPAIR_SCHEDULER_MIN_INTERVAL_SECS: u64 = 60;
const CONTENT_REPAIR_SCHEDULER_DEFAULT_INTERVAL_SECS: u64 = 15 * 60;
const CONTENT_REPAIR_SCHEDULER_DEFAULT_LIMIT: u64 = 10;
const CONTENT_REPAIR_SCHEDULER_DEFAULT_MAX_ATTEMPTS: u64 = 3;
const CONTENT_REPAIR_SCHEDULER_DEFAULT_FAILURE_BUDGET: u64 = 5;
const BROWSER_ENGINE_PROVIDER_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const MODEL_PROVIDER_ID: &str = "model-provider";
const MODEL_PROVIDER_PROTOCOL_VERSION: &str = "elastos.model-provider/v1";
const MODEL_PROVIDER_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(all(test, unix))]
const MODEL_PROVIDER_CONFIG_FILE_NAME: &str = "config.json";
#[cfg(all(test, unix))]
const MODEL_PROVIDER_CONFIG_MAX_BYTES: usize = 256 * 1024;
const MEDIA_PROVIDER_ID: &str = "media-provider";
const MEDIA_PROVIDER_ROUTE: &str = "media";
#[cfg(all(test, unix))]
const MEDIA_PROVIDER_PROTOCOL_VERSION: &str = "elastos.media-provider/v1";
const MEDIA_PROVIDER_STATUS_TIMEOUT: Duration = Duration::from_secs(5);
const WALLET_PROVIDER_STATUS_TIMEOUT: Duration = Duration::from_secs(5);

fn report_missing_home_provider(data_dir: &Path, name: &str, consequence: &str) {
    let required = match std::fs::read(data_dir.join("components.json")) {
        Ok(bytes) => serde_json::from_slice::<elastos_server::setup::ComponentsManifest>(&bytes)
            .map(|manifest| {
                manifest.profiles.get("home").is_some_and(|profile| {
                    profile.components.iter().any(|component| component == name)
                })
            })
            .unwrap_or(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    };
    if required {
        tracing::warn!("{name} binary is not installed; {consequence}");
    } else {
        tracing::debug!("{name} binary is not installed; {consequence}");
    }
}

#[cfg(all(test, unix))]
use api::model_provider_bridge_config;
use api::model_provider_config as model_provider_startup_config;
#[cfg(all(test, unix))]
fn model_provider_root_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("providers").join(MODEL_PROVIDER_ID)
}

#[cfg(all(test, unix))]
fn model_provider_config_path(data_dir: &Path) -> PathBuf {
    model_provider_root_dir(data_dir).join(MODEL_PROVIDER_CONFIG_FILE_NAME)
}

#[cfg(all(test, unix))]
fn model_provider_journal_dir(data_dir: &Path) -> PathBuf {
    model_provider_root_dir(data_dir).join("journal")
}

use elastos_server::protected_content_runtime::derive_protected_content_runtime_issuer;

fn chain_provider_bridge_config_without_protected_network(
    runtime_operation_issuer: &elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
) -> provider::BridgeProviderConfig {
    provider::BridgeProviderConfig {
        extra: serde_json::json!({
            "protected_content_runtime_issuer": format!(
                "0x{}",
                hex::encode(runtime_operation_issuer.as_bytes())
            )
        }),
        ..Default::default()
    }
}

fn chain_provider_bridge_config(
    data_dir: &Path,
    runtime_operation_issuer: &elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
) -> anyhow::Result<provider::BridgeProviderConfig> {
    let protected_content_config =
        elastos_server::protected_content_runtime::load_runtime_protected_content_chain_provider_config(
            data_dir,
        )?;
    let mut config =
        chain_provider_bridge_config_without_protected_network(runtime_operation_issuer);
    if let Some(protected_content_config) = protected_content_config {
        config.extra["protected_content_network"] =
            protected_content_config.protected_content_network().clone();
    }
    Ok(config)
}

fn chain_provider_protected_startup_config(
    data_dir: &Path,
    runtime_operation_issuer: &elastos_protected_content_contracts::RuntimeOperationIssuerKeyV1,
) -> Option<provider::BridgeProviderConfig> {
    match chain_provider_bridge_config(data_dir, runtime_operation_issuer) {
        Ok(config) if config.extra.get("protected_content_network").is_some() => Some(config),
        Ok(_) => None,
        Err(_) => {
            tracing::warn!(
                "Protected-content Chain configuration is invalid; protected operations remain unavailable"
            );
            None
        }
    }
}

#[cfg(all(test, unix))]
fn media_provider_root_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("protected-content").join(MEDIA_PROVIDER_ID)
}

#[cfg(all(test, unix))]
fn media_provider_config_path(data_dir: &Path) -> PathBuf {
    media_provider_root_dir(data_dir).join("config.json")
}

fn media_provider_bridge_config(
    data_dir: &Path,
) -> anyhow::Result<Option<provider::BridgeProviderConfig>> {
    elastos_server::protected_content_runtime::load_runtime_media_provider_bridge_config(data_dir)
}

/// The model provider starts only under an OS confinement backend. The launcher
/// refuses startup on any other OS instead of running the model unconfined.
const MODEL_PROVIDER_CONFINEMENT_UNAVAILABLE: &str = "provider confinement unavailable on this OS";

fn model_provider_confinement(os: &str) -> Result<(), provider::bridge::BridgeError> {
    match os {
        "macos" | "linux" => Ok(()),
        _ => Err(provider::bridge::BridgeError::InitFailed(
            MODEL_PROVIDER_CONFINEMENT_UNAVAILABLE.to_owned(),
        )),
    }
}

async fn request_browser_engine_provider_status(
    bridge: &provider::ProviderBridge,
    status_timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    tokio::time::timeout(
        status_timeout,
        bridge.send_raw(&serde_json::json!({"op": "status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("browser-engine-adapter status request timed out"))?
    .map_err(|err| anyhow::anyhow!("browser-engine-adapter status request failed: {err}"))
}

async fn start_browser_engine_provider(
    registry: &provider::ProviderRegistry,
    bridge: Arc<provider::ProviderBridge>,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let startup = async {
        let status = request_browser_engine_provider_status(&bridge, status_timeout).await?;
        require_browser_engine_provider_status(&status)?;
        let browser_engine_provider: Arc<dyn provider::Provider> = Arc::new(
            provider::CapsuleProvider::with_scheme(bridge.clone(), "browser-engine"),
        );
        register_browser_engine_provider(registry, browser_engine_provider).await
    }
    .await;
    if let Err(startup_error) = startup {
        if let Err(shutdown_error) = bridge.shutdown().await {
            return Err(anyhow::anyhow!(
                "{startup_error}; browser-engine-adapter shutdown/reap also failed: {shutdown_error}"
            ));
        }
        return Err(startup_error);
    }
    Ok(())
}

fn require_browser_engine_provider_status(status: &serde_json::Value) -> anyhow::Result<()> {
    if status.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        anyhow::bail!("browser-engine-adapter status request did not succeed");
    }
    let data = status
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("browser-engine-adapter status is missing data"))?;
    if data.get("provider").and_then(serde_json::Value::as_str) != Some(BROWSER_ENGINE_PROVIDER_ID)
    {
        anyhow::bail!("browser-engine-adapter status has an unsupported provider identity");
    }
    if data
        .get("protocol_version")
        .and_then(serde_json::Value::as_str)
        != Some(BROWSER_ENGINE_PROTOCOL_VERSION)
    {
        anyhow::bail!("browser-engine-adapter status has an unsupported protocol version");
    }
    Ok(())
}

async fn register_browser_engine_provider(
    registry: &provider::ProviderRegistry,
    browser_engine_provider: Arc<dyn provider::Provider>,
) -> anyhow::Result<()> {
    if registry
        .registration_for_uri("elastos://browser-engine/status")
        .await
        .is_some()
    {
        anyhow::bail!("failed to register Browser Engine provider: route already registered");
    }
    registry
        .register_sub_provider("browser-engine", browser_engine_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register Browser Engine provider: {err}"))
}

async fn request_wallet_provider_v2_status(
    bridge: &provider::ProviderBridge,
    status_timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    tokio::time::timeout(
        status_timeout,
        bridge.send_raw(&serde_json::json!({"op": "status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("wallet-provider status request timed out"))?
    .map_err(|err| anyhow::anyhow!("wallet-provider status request failed: {err}"))
}

async fn check_wallet_provider_v2_status(
    bridge: &provider::ProviderBridge,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let status = request_wallet_provider_v2_status(bridge, status_timeout).await?;
    require_wallet_provider_v2_status(&status)
}

async fn start_wallet_provider_v2(
    registry: &provider::ProviderRegistry,
    confined: provider::Confined,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let bridge = Arc::clone(confined.bridge());
    let wallet_provider: Arc<dyn provider::Provider> =
        Arc::new(provider::CapsuleProvider::from_confined(confined, "wallet"));
    check_and_register_wallet_provider_v2(registry, bridge, wallet_provider, status_timeout).await
}

/// Check the bounded status, then register the provider. A status or
/// registration failure sends Shutdown, reaps the child, and reports both
/// errors when the shutdown also fails.
async fn check_and_register_wallet_provider_v2(
    registry: &provider::ProviderRegistry,
    bridge: Arc<provider::ProviderBridge>,
    wallet_provider: Arc<dyn provider::Provider>,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let startup = async {
        check_wallet_provider_v2_status(&bridge, status_timeout).await?;
        register_wallet_provider_v2(registry, wallet_provider).await
    }
    .await;
    if let Err(startup_error) = startup {
        if let Err(shutdown_error) = bridge.shutdown().await {
            return Err(anyhow::anyhow!(
                "{startup_error}; wallet-provider shutdown/reap also failed: {shutdown_error}"
            ));
        }
        return Err(startup_error);
    }
    Ok(())
}

#[cfg(any(
    test,
    elastos_unsupported_os_check,
    not(any(
        target_os = "macos",
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))
))]
const WALLET_UNSUPPORTED_OS: &str = "provider start is refused: this operating system has no confinement, so the provider binary does not start";

/// Return the Runtime's confined-start refusal before creating `SystemServices`.
/// The row below checks these texts against the Runtime's private OS entry.
fn wallet_confinement_refusal() -> Option<&'static str> {
    #[cfg(all(
        not(elastos_unsupported_os_check),
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        None
    }
    #[cfg(all(not(elastos_unsupported_os_check), target_os = "macos"))]
    {
        // The Runtime starts the wallet under its Seatbelt profile here.
        None
    }
    #[cfg(any(
        elastos_unsupported_os_check,
        not(any(
            target_os = "macos",
            all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            )
        ))
    ))]
    {
        Some(WALLET_UNSUPPORTED_OS)
    }
}

/// Create the wallet storage parent at 0700 when missing, or tighten an
/// existing directory of ours so the confined entry accepts it.
///
/// `spawn_confined` creates `Wallet` at 0700 and opens its parent only when that
/// parent is our non-symlink directory with no group or other write permission.
/// A fresh source Home creates only `ElastOS`, while other services create
/// `SystemServices` under the umask (0775 under umask 002), so the Runtime fills
/// a missing level at 0700 and removes group and other write bits from an
/// existing one. Inspect and tighten the same opened directory, after checking
/// its owner. The confined entry checks the storage root again at launch.
#[cfg(unix)]
fn tighten_wallet_parent(directory: &std::fs::File, effective_uid: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = directory.metadata()?;
    if metadata.uid() != effective_uid {
        anyhow::bail!("wallet storage parent has a foreign owner");
    }
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        directory.set_permissions(std::fs::Permissions::from_mode(mode & 0o7777 & !0o022))?;
    }
    Ok(())
}

/// Windows has no owner-checked, no-follow wallet storage parent yet; the wallet
/// start refuses there before this point, and this refuses as well.
#[cfg(windows)]
fn prepare_wallet_storage_parent(_wallet_root: &Path) -> anyhow::Result<()> {
    anyhow::bail!("wallet storage is unsupported on Windows")
}

#[cfg(unix)]
fn prepare_wallet_storage_parent(wallet_root: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let parent = wallet_root
        .parent()
        .ok_or_else(|| anyhow::anyhow!("wallet storage root has no parent directory"))?;
    let open_parent = || {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)
    };
    let directory = match open_parent() {
        Ok(directory) => directory,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(parent)
                .map_err(|err| {
                    anyhow::anyhow!(
                        "cannot prepare wallet storage parent {}: {err}",
                        parent.display()
                    )
                })?;
            open_parent().map_err(|err| {
                anyhow::anyhow!(
                    "cannot open wallet storage parent {}: {err}",
                    parent.display()
                )
            })?
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => {
            anyhow::bail!(
                "wallet storage parent is not a directory: {}",
                parent.display()
            )
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "cannot open wallet storage parent {}: {err}",
                parent.display()
            ))
        }
    };
    tighten_wallet_parent(&directory, unsafe { libc::geteuid() }).map_err(|err| {
        anyhow::anyhow!(
            "cannot tighten wallet storage parent {}: {err}",
            parent.display()
        )
    })?;
    Ok(())
}

/// Object-provider init config. The encryption field is empty.
///
/// `init` reads `base_path` only. Existing object bytes are not encrypted
/// under Home's device key. The child is still unconfined, and `base_path`
/// is the data directory, so it can open `identity/device.key`.
fn object_provider_bridge_config(data_dir: &Path) -> provider::BridgeProviderConfig {
    provider::BridgeProviderConfig {
        base_path: data_dir.to_string_lossy().to_string(),
        allowed_paths: file_backed_prefixes(),
        read_only: false,
        encryption_key: String::new(),
        ..Default::default()
    }
}

/// Wallet-provider init config. The encryption field is empty.
///
/// Wallet files use the random `wallet-key.hex` in the wallet directory.
/// They were never encrypted under Home's device key. The local below is
/// empty. It is not a device key. Its name is the authority-census needle
/// for the row `elastos-server/src/server_infra.rs` /
/// `wallet_provider_bridge_config` / `encryption_key: device_key_hex`
/// in `home_held_authority`.
fn wallet_provider_bridge_config(data_dir: &Path) -> provider::BridgeProviderConfig {
    let device_key_hex = String::new();
    provider::BridgeProviderConfig {
        base_path: data_dir.to_string_lossy().to_string(),
        allowed_paths: file_backed_prefixes(),
        read_only: false,
        encryption_key: device_key_hex,
        ..Default::default()
    }
}

async fn start_wallet_provider(
    data_dir: &Path,
    provider_registry: &provider::ProviderRegistry,
    status_timeout: Duration,
) -> anyhow::Result<Option<Arc<provider::ProviderBridge>>> {
    let Some(admitted) = binaries::AdmittedProvider::admit(data_dir, "wallet-provider")? else {
        return Ok(None);
    };
    if let Some(refusal) = wallet_confinement_refusal() {
        anyhow::bail!(refusal);
    }
    // The bridge re-checks the admitted signed digest at spawn and starts the
    // bytes it checked; check before the Home's storage is touched.
    let checked = admitted
        .checked_executable(data_dir)
        .map_err(anyhow::Error::msg)?;
    let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
    prepare_wallet_storage_parent(&wallet_root)?;
    let wallet_config = wallet_provider_bridge_config(data_dir);
    let confined = provider::ProviderBridge::spawn_confined(
        admitted.key(),
        admitted.authority(),
        &checked,
        &wallet_root,
        wallet_config,
    )
    .await
    .map_err(|err| anyhow::anyhow!("Failed to spawn wallet-provider: {err}"))?;
    let bridge = Arc::clone(confined.bridge());
    start_wallet_provider_v2(provider_registry, confined, status_timeout).await?;
    tracing::info!(
        "wallet-provider v2 capsule from {}",
        admitted.path().display()
    );
    Ok(Some(bridge))
}

async fn request_model_provider_status(
    bridge: &provider::ProviderBridge,
    status_timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    tokio::time::timeout(
        status_timeout,
        bridge.send_raw(&serde_json::json!({"op": "status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("model-provider status request timed out"))?
    .map_err(|err| anyhow::anyhow!("model-provider status request failed: {err}"))
}

async fn start_model_provider(
    registry: &provider::ProviderRegistry,
    bridge: Arc<provider::ProviderBridge>,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let startup = async {
        let status = request_model_provider_status(&bridge, status_timeout).await?;
        require_model_provider_status(&status)?;
        let model_provider: Arc<dyn provider::Provider> = Arc::new(
            provider::CapsuleProvider::with_scheme(bridge.clone(), "model"),
        );
        register_model_provider(registry, model_provider).await
    }
    .await;
    if let Err(startup_error) = startup {
        if let Err(shutdown_error) = bridge.shutdown().await {
            return Err(anyhow::anyhow!(
                "{startup_error}; model-provider shutdown/reap also failed: {shutdown_error}"
            ));
        }
        return Err(startup_error);
    }
    Ok(())
}

async fn request_media_provider_status(
    bridge: &provider::ProviderBridge,
    status_timeout: Duration,
) -> anyhow::Result<serde_json::Value> {
    tokio::time::timeout(
        status_timeout,
        bridge.send_raw(&serde_json::json!({"op": "status"})),
    )
    .await
    .map_err(|_| anyhow::anyhow!("media-provider status request timed out"))?
    .map_err(|_| anyhow::anyhow!("media-provider status request failed"))
}

async fn start_media_provider(
    registry: &provider::ProviderRegistry,
    bridge: Arc<provider::ProviderBridge>,
    status_timeout: Duration,
) -> anyhow::Result<()> {
    let startup = async {
        let status = request_media_provider_status(&bridge, status_timeout).await?;
        elastos_server::protected_content_runtime::require_media_provider_status(&status)?;
        let media_provider: Arc<dyn provider::Provider> = Arc::new(
            provider::CapsuleProvider::with_scheme(bridge.clone(), MEDIA_PROVIDER_ROUTE),
        );
        register_media_provider(registry, media_provider).await
    }
    .await;
    if let Err(startup_error) = startup {
        if let Err(shutdown_error) = bridge.shutdown().await {
            return Err(anyhow::anyhow!(
                "{startup_error}; media-provider shutdown/reap also failed: {shutdown_error}"
            ));
        }
        return Err(startup_error);
    }
    Ok(())
}

fn require_wallet_provider_v2_status(status: &serde_json::Value) -> anyhow::Result<()> {
    if status.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        anyhow::bail!("wallet-provider status request did not succeed");
    }
    let data = status
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("wallet-provider status is missing data"))?;
    if data.get("provider").and_then(serde_json::Value::as_str) != Some("wallet-provider") {
        anyhow::bail!("wallet-provider status has an unsupported provider identity");
    }
    if data
        .get("protocol_version")
        .and_then(serde_json::Value::as_str)
        != Some(WALLET_PROTOCOL_VERSION)
    {
        anyhow::bail!("wallet-provider status has an unsupported protocol version");
    }
    Ok(())
}

fn require_model_provider_status(status: &serde_json::Value) -> anyhow::Result<()> {
    if status.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        anyhow::bail!("model-provider status request did not succeed");
    }
    let data = status
        .get("data")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("model-provider status is missing data"))?;
    if data.get("provider").and_then(serde_json::Value::as_str) != Some(MODEL_PROVIDER_ID) {
        anyhow::bail!("model-provider status has an unsupported provider identity");
    }
    if data
        .get("protocol_version")
        .and_then(serde_json::Value::as_str)
        != Some(MODEL_PROVIDER_PROTOCOL_VERSION)
    {
        anyhow::bail!("model-provider status has an unsupported protocol version");
    }
    Ok(())
}

async fn register_wallet_provider_v2(
    registry: &provider::ProviderRegistry,
    wallet_provider: Arc<dyn provider::Provider>,
) -> anyhow::Result<()> {
    registry
        .register_sub_provider("wallet", wallet_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register Wallet provider v2: {err}"))
}

async fn register_model_provider(
    registry: &provider::ProviderRegistry,
    model_provider: Arc<dyn provider::Provider>,
) -> anyhow::Result<()> {
    if registry
        .registration_for_uri("elastos://model/offers")
        .await
        .is_some()
    {
        anyhow::bail!("failed to register model provider: route already registered");
    }
    registry
        .register_sub_provider("model", model_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register model provider: {err}"))
}

async fn register_media_provider(
    registry: &provider::ProviderRegistry,
    media_provider: Arc<dyn provider::Provider>,
) -> anyhow::Result<()> {
    if registry
        .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
        .await
    {
        anyhow::bail!("failed to register media provider: route already registered");
    }
    registry
        .register_runtime_provider_target(MEDIA_PROVIDER_ROUTE, media_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register media provider: {err}"))
}

/// `elastos gateway` and `elastos home --browser` do not spawn the localhost
/// helper. They still run the walk. A refusal is registered so System's
/// inspect state is that sentence.
async fn register_localhost_without_helper(
    registry: &provider::ProviderRegistry,
    data_dir: &Path,
    device_key: &[u8; 32],
) {
    if let crate::localhost_file_migration::LocalhostBringup::Refuse(sentence) =
        crate::localhost_file_migration::localhost_bringup(data_dir, device_key)
    {
        tracing::error!(target: "elastos", "{sentence}");
        registry
            .register(Arc::new(
                elastos_server::local_apps::RefusingLocalhostProvider::new(sentence),
            ))
            .await;
    }
}

pub(crate) async fn setup_server_infrastructure() -> anyhow::Result<ServerInfrastructure> {
    setup_server_infrastructure_impl(true, elastos_server::ipfs::IpfsHostRole::User).await
}

pub(crate) async fn setup_control_plane_infrastructure() -> anyhow::Result<ServerInfrastructure> {
    setup_server_infrastructure_impl(false, elastos_server::ipfs::IpfsHostRole::User).await
}

pub(crate) async fn setup_gateway_infrastructure() -> anyhow::Result<ServerInfrastructure> {
    setup_server_infrastructure_impl(false, elastos_server::ipfs::IpfsHostRole::Gateway).await
}

// ---------------------------------------------------------------------------
// Core planes shared by every composition profile — the full runtime host
// (`setup_server_infrastructure`), the control plane, and the standalone
// provider host (`provider_host`). Each returns `Result` so a profile that
// must fail closed can, while the runtime host keeps warning and degrading.
// ---------------------------------------------------------------------------

/// Register the in-process content plane: the `content` scheme provider and
/// the `elastos://content` sub-provider a Carrier replica receive dispatches
/// to for `import_exact`.
pub(crate) async fn register_content_plane(
    provider_registry: &Arc<provider::ProviderRegistry>,
    data_dir: &Path,
) -> anyhow::Result<Arc<ContentProvider>> {
    let content_provider = Arc::new(ContentProvider::new(
        data_dir.to_path_buf(),
        Arc::downgrade(provider_registry),
    ));
    provider_registry.register(content_provider.clone()).await;
    provider_registry
        .register_sub_provider("content", content_provider.clone())
        .await
        .map_err(|err| {
            anyhow::anyhow!("failed to register elastos://content sub-provider: {err}")
        })?;
    Ok(content_provider)
}

/// Spawn the ipfs-provider capsule and register `elastos://ipfs`, the block
/// backend the content plane pins imported objects through.
#[cfg(unix)]
pub(crate) async fn register_ipfs_provider_plane(
    provider_registry: &Arc<provider::ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    register_ipfs_provider_plane_with_role(
        provider_registry,
        binary_path,
        elastos_server::ipfs::IpfsHostRole::User,
        data_dir,
    )
    .await
}

/// `data_dir` is the Home this plane serves; the provider executable is
/// admitted against that Home's signed release.
async fn register_ipfs_provider_plane_with_role(
    provider_registry: &Arc<provider::ProviderRegistry>,
    binary_path: &Path,
    role: elastos_server::ipfs::IpfsHostRole,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let config = elastos_server::ipfs::ipfs_provider_config(role);
    let bridge = provider::ProviderBridge::spawn(
        &checked_native_provider_with_data_dir(data_dir, binary_path),
        config,
    )
    .await
    .map_err(|err| anyhow::anyhow!("failed to spawn ipfs-provider: {err}"))?;
    let ipfs_provider: Arc<dyn provider::Provider> = Arc::new(
        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "ipfs"),
    );
    provider_registry
        .register_sub_provider("ipfs", ipfs_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register elastos://ipfs sub-provider: {err}"))
}

/// Spawn the availability-provider capsule and register `elastos://availability`.
/// `data_dir` is the Home this plane serves; the provider executable is
/// admitted against that Home's signed release.
pub(crate) async fn register_availability_provider_plane(
    provider_registry: &Arc<provider::ProviderRegistry>,
    binary_path: &Path,
    config: serde_json::Value,
    data_dir: &Path,
) -> anyhow::Result<()> {
    let bridge = provider::ProviderBridge::spawn(
        &checked_native_provider_with_data_dir(data_dir, binary_path),
        provider::BridgeProviderConfig {
            extra: config,
            ..Default::default()
        },
    )
    .await
    .map_err(|err| anyhow::anyhow!("failed to spawn availability-provider: {err}"))?;
    let availability_provider: Arc<dyn provider::Provider> = Arc::new(
        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "availability"),
    );
    provider_registry
        .register_sub_provider("availability", availability_provider)
        .await
        .map_err(|err| {
            anyhow::anyhow!("failed to register elastos://availability sub-provider: {err}")
        })
}

/// Spawn the chain-provider capsule with this data dir's protected-content
/// network configuration applied and register `elastos://chain`.
///
/// A standalone custody host needs this plane: a committee member settles
/// every release through its own `protected_content_rights_evidence` call,
/// so the configuration is required here (the full Home profile tolerates its
/// absence because it degrades protected operations, not the whole host).
#[cfg(unix)]
pub(crate) async fn register_chain_provider_plane(
    provider_registry: &Arc<provider::ProviderRegistry>,
    binary_path: &Path,
    data_dir: &Path,
) -> anyhow::Result<()> {
    // The chain plane verifies every signed Runtime release operation it
    // evaluates against one issuer. On a custody committee member that must
    // be the CLIENT Runtime the custody state was provisioned to trust (the
    // operations are signed there), never this host's own device key; a
    // host without provisioned custody state (the full Home profile, or a
    // chain-only host) is its own Runtime and keeps the device-key issuer.
    let custody_state_root =
        elastos_server::protected_content_runtime::inactive_custody_state_root(data_dir);
    let runtime_issuer = if custody_state_root.is_dir() {
        let issuer = custody_provider::load_trusted_runtime_issuer(&custody_state_root).map_err(
            |error| {
                anyhow::anyhow!(
                    "provisioned custody state names no readable trusted Runtime issuer: {error:?}"
                )
            },
        )?;
        tracing::info!(
            issuer = %format!("0x{}", hex::encode(issuer.as_bytes())),
            "chain plane trusts the custody state's provisioned Runtime issuer"
        );
        issuer
    } else {
        let device_key = elastos_identity::load_or_create_device_key(data_dir)
            .context("chain-provider host identity is unavailable")?;
        derive_protected_content_runtime_issuer(&device_key)?
    };
    let config = chain_provider_bridge_config(data_dir, &runtime_issuer)
        .context("protected-content chain configuration is invalid")?;
    if config.extra.get("protected_content_network").is_none() {
        anyhow::bail!("protected-content chain configuration names no protected_content_network");
    }
    let generic_config = chain_provider_bridge_config_without_protected_network(&runtime_issuer);
    // Admit against the signed release of the Home this chain plane serves.
    let bridge = provider::ProviderBridge::spawn(
        &checked_native_provider_with_data_dir(data_dir, binary_path),
        generic_config,
    )
    .await
    .map_err(|err| anyhow::anyhow!("failed to spawn chain-provider: {err}"))?;
    match bridge
        .request(provider::bridge::ProviderRequest::Init { config })
        .await
    {
        Ok(provider::bridge::ProviderResponse::Ok { .. }) => {}
        Ok(provider::bridge::ProviderResponse::Error { code, message, .. }) => {
            let _ = bridge.shutdown().await;
            anyhow::bail!(
                "chain-provider rejected the protected-content chain configuration: {code}: {message}"
            );
        }
        Err(err) => {
            let _ = bridge.shutdown().await;
            anyhow::bail!("chain-provider transport failed while applying configuration: {err}");
        }
    }
    let chain_provider: Arc<dyn provider::Provider> = Arc::new(
        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "chain"),
    );
    provider_registry
        .register_sub_provider("chain", chain_provider)
        .await
        .map_err(|err| anyhow::anyhow!("failed to register elastos://chain sub-provider: {err}"))
}

/// Start the Carrier node and wire it as the registry's provider invoker, so
/// inbound `provider_invoke` frames dispatch into this registry and outbound
/// invocations can route over Carrier.
pub(crate) async fn start_carrier_plane(
    provider_registry: &Arc<provider::ProviderRegistry>,
    signing_key: &ed25519_dalek::SigningKey,
    did: &str,
    data_dir: &Path,
    bind_addr: Option<std::net::SocketAddr>,
    community_bootstrap_node_ids: &[String],
) -> anyhow::Result<elastos_server::carrier::CarrierNode> {
    let carrier_node = elastos_server::carrier::start_carrier_node_with_registry_bound(
        signing_key,
        did,
        data_dir.to_path_buf(),
        Some(Arc::downgrade(provider_registry)),
        bind_addr,
        community_bootstrap_node_ids,
    )
    .await?;
    provider_registry
        .set_carrier_invoker(Arc::new(
            elastos_server::carrier::CarrierProviderInvoker::with_carrier_endpoint_and_registry(
                carrier_node.endpoint.clone(),
                Arc::downgrade(provider_registry),
            ),
        ))
        .await;
    Ok(carrier_node)
}

async fn serve_capability_store(
    data_dir: &Path,
) -> anyhow::Result<Arc<capability::CapabilityStore>> {
    api::handlers::settle::open_capability_store(data_dir)
        .await
        .map(Arc::new)
        .map_err(|err| anyhow::anyhow!("capability store unavailable: {err}"))
}

/// DID-provider init config.
///
/// The child receives the device signing seed and the existing
/// `elastos-did-storage` key. It does not receive the raw device key.
/// The local below is the storage-key hex. It is not the raw device key.
/// Its name is the authority-census needle for the row
/// `elastos-server/src/server_infra.rs` / `did_provider_bridge_config` /
/// `encryption_key: device_key_hex` in `home_held_authority`.
pub(crate) fn did_provider_bridge_config(
    data_dir: &Path,
    device_key: &[u8; 32],
) -> provider::BridgeProviderConfig {
    let signing_seed = elastos_identity::derive_did_seed(device_key);
    let storage_key = elastos_identity::derive_storage_key(device_key);
    let device_key_hex = hex::encode(storage_key);
    provider::BridgeProviderConfig {
        base_path: data_dir.to_string_lossy().to_string(),
        allowed_paths: file_backed_prefixes(),
        read_only: false,
        encryption_key: device_key_hex,
        extra: serde_json::json!({
            "signing_seed": hex::encode(signing_seed),
        }),
    }
}

async fn start_did_provider(
    data_dir: &Path,
    provider_registry: &provider::ProviderRegistry,
    device_key: &[u8; 32],
) -> anyhow::Result<Option<Arc<provider::ProviderBridge>>> {
    // Refuse a symlink root before admission reads the signed release through it.
    if std::fs::symlink_metadata(data_dir).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        anyhow::bail!("provider start is refused: the storage root's parent is a symlink");
    }
    let Some(admitted) = binaries::AdmittedProvider::admit(data_dir, "did-provider")? else {
        return Ok(None);
    };
    let data_dir_metadata = std::fs::symlink_metadata(data_dir).with_context(|| {
        format!(
            "failed to inspect DID provider data root {}",
            data_dir.display()
        )
    })?;
    if data_dir_metadata.file_type().is_symlink() {
        anyhow::bail!("provider start is refused: the storage root's parent is a symlink");
    }
    let confined_data_dir = std::fs::canonicalize(data_dir).with_context(|| {
        format!(
            "failed to resolve DID provider data root {}",
            data_dir.display()
        )
    })?;
    let did_config = did_provider_bridge_config(&confined_data_dir, device_key);
    // The bridge re-checks the admitted signed digest at spawn and starts the
    // bytes it checked.
    let checked = admitted
        .checked_executable(data_dir)
        .map_err(anyhow::Error::msg)?;
    let confined = provider::ProviderBridge::spawn_confined(
        admitted.key(),
        admitted.authority(),
        &checked,
        &confined_data_dir.join("did"),
        did_config,
    )
    .await
    .map_err(|err| anyhow::anyhow!("Failed to spawn did-provider: {err}"))?;
    let bridge = Arc::clone(confined.bridge());
    let provider: Arc<dyn provider::Provider> =
        Arc::new(provider::CapsuleProvider::from_confined(confined, "did"));
    if let Err(registration_error) = provider_registry
        .register_sub_provider("did", provider)
        .await
    {
        let shutdown_error = bridge.shutdown().await.err();
        if let Some(shutdown_error) = shutdown_error {
            anyhow::bail!(
                "Failed to register elastos://did sub-provider: {registration_error}; shutdown failed: {shutdown_error}"
            );
        }
        anyhow::bail!("Failed to register elastos://did sub-provider: {registration_error}");
    }
    tracing::info!("did-provider capsule from {}", admitted.path().display());
    Ok(Some(bridge))
}

async fn start_did_provider_for_server(
    data_dir: &Path,
    provider_registry: &provider::ProviderRegistry,
    device_key: &[u8; 32],
) -> anyhow::Result<()> {
    if let Err(err) = start_did_provider(data_dir, provider_registry, device_key).await {
        tracing::warn!("Skipping did-provider: {}", err);
        return Err(err);
    }
    Ok(())
}

async fn setup_server_infrastructure_impl(
    spawn_host_providers: bool,
    ipfs_role: elastos_server::ipfs::IpfsHostRole,
) -> anyhow::Result<ServerInfrastructure> {
    let data_dir = default_data_dir();
    // Before ensure_file_backed_roots recreates AppCapsules, ElastOS, Local,
    // Users, and UsersAI. Gateway calls the same function before its auth lock.
    crate::localhost_file_migration::prepare_localhost_files(&data_dir)?;
    let carrier_bind_addr = configured_carrier_bind_addr(&data_dir)?;
    let _ = ownership::repair_path_recursive(&data_dir);
    let collaboration_configuration =
        elastos_server::collaboration_startup::load_and_accept_collaboration_startup_configuration(
            &data_dir,
        )?;

    let audit_log = Arc::new(primitives::audit::AuditLog::new());
    let session_registry = Arc::new(session::SessionRegistry::new(audit_log.clone()));
    session_registry
        .set_default_owner(local_session_owner(&data_dir)?)
        .await;
    let metrics = Arc::new(primitives::metrics::MetricsManager::new());
    let capability_store = serve_capability_store(&data_dir).await?;
    let capability_manager = Arc::new(capability::CapabilityManager::load_or_generate(
        &data_dir,
        capability_store.clone(),
        audit_log.clone(),
        metrics.clone(),
    ));
    let pending_store = Arc::new(capability::pending::PendingRequestStore::new(
        audit_log.clone(),
    ));

    let tls_config = match elastos_tls::load_or_create_tls_config(&data_dir).await {
        Ok(config) => {
            tracing::info!("TLS enabled (self-signed CA)");
            Some(config)
        }
        Err(e) => {
            tracing::warn!("TLS disabled: {}. Running without HTTPS.", e);
            None
        }
    };

    ensure_file_backed_roots(&data_dir).ok();
    elastos_server::protected_content_runtime::log_unresolved_runtime_releases(&data_dir);
    let provider_registry = Arc::new(provider::ProviderRegistry::new());
    let mut managed_host_processes = Vec::new();
    let mut external_availability_registered = false;
    let mut carrier_service = None;
    let content_plane = match register_content_plane(&provider_registry, &data_dir).await {
        Ok(provider) => Some(provider),
        Err(err) => {
            tracing::warn!("{}", err);
            None
        }
    };
    provider_registry
        .register(Arc::new(DocumentsProvider::new(
            data_dir.clone(),
            Arc::downgrade(&provider_registry),
        )))
        .await;
    let inspect_source: Arc<dyn elastos_server::inspect_provider::InspectSource> = Arc::new(
        elastos_server::inspect_provider::AggregateInspectSource::new(vec![
            Arc::new(elastos_server::inspect_provider::CatalogInspectSource::new(
                data_dir.join("capsules"),
                Arc::downgrade(&provider_registry),
                data_dir.clone(),
            )),
            Arc::new(
                elastos_server::inspect_provider::RegistryInspectSource::new(
                    Arc::downgrade(&provider_registry),
                    data_dir.clone(),
                ),
            ),
        ]),
    );
    let inspect_provider: Arc<dyn provider::Provider> = Arc::new(
        elastos_server::inspect_provider::InspectProvider::with_registry(
            inspect_source,
            Arc::downgrade(&provider_registry),
        ),
    );
    provider_registry.register(inspect_provider.clone()).await;
    if let Err(err) = provider_registry
        .register_sub_provider("inspect", inspect_provider)
        .await
    {
        tracing::warn!("Failed to register elastos://inspect sub-provider: {}", err);
    }
    let device_key = elastos_identity::load_or_create_device_key(&data_dir)?;
    let protected_content_runtime_issuer = derive_protected_content_runtime_issuer(&device_key)?;
    let mut provider_cid = "sha256:unavailable".to_string();
    let verify_provider_binary = |name: &str, path: &std::path::Path| -> anyhow::Result<()> {
        let checksum = crate::setup::verify_installed_component_binary(&data_dir, name, path)?;
        tracing::info!(
            "{} binary verified against installed manifest ({})",
            name,
            checksum
        );
        Ok(())
    };

    let _ = start_did_provider_for_server(&data_dir, &provider_registry, &device_key).await;

    if spawn_host_providers {
        let binary_path = binaries::resolve_verified_native_provider_binary("localhost-provider")?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "localhost-provider not installed.\n  \
                 Run:\n  \
                   elastos setup --with localhost-provider"
                )
            })?;

        let provider_bytes = std::fs::read(binary_path.path())?;
        provider_cid = format!(
            "sha256:{}",
            hex::encode(elastos_runtime::signature::hash_content(&provider_bytes))
        );

        match crate::localhost_file_migration::localhost_bringup(&data_dir, &device_key) {
            crate::localhost_file_migration::LocalhostBringup::Start(config) => {
                let bridge = provider::ProviderBridge::spawn(&binary_path, config)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to spawn localhost-provider capsule: {}.\n  \
                             Reinstall with:\n  \
                               elastos setup --with localhost-provider",
                            e
                        )
                    })?;
                tracing::info!(
                    "localhost-provider capsule {} from {}",
                    provider_cid,
                    binary_path.display()
                );
                let provider: Arc<dyn provider::Provider> =
                    Arc::new(provider::CapsuleProvider::new(Arc::new(bridge)));
                provider_registry.register(provider).await;
            }
            crate::localhost_file_migration::LocalhostBringup::Refuse(sentence) => {
                tracing::error!(target: "elastos", "{sentence}");
                provider_registry
                    .register(Arc::new(
                        elastos_server::local_apps::RefusingLocalhostProvider::new(sentence),
                    ))
                    .await;
            }
        }

        if let Some(availability_config) = availability_provider_config_from_env() {
            if let Some(path) = crate::find_installed_provider_binary("availability-provider") {
                if let Err(e) = verify_provider_binary("availability-provider", &path) {
                    tracing::warn!(
                        "Skipping availability-provider due to verification failure: {}",
                        e
                    );
                } else {
                    match register_availability_provider_plane(
                        &provider_registry,
                        &path,
                        availability_config,
                        &data_dir,
                    )
                    .await
                    {
                        Ok(()) => {
                            external_availability_registered = true;
                            tracing::info!("availability-provider capsule from {}", path.display());
                        }
                        Err(e) => tracing::warn!("{}", e),
                    }
                }
            } else {
                tracing::warn!(
                    "Availability provider configured but availability-provider binary is not installed"
                );
            }
        }
    } else {
        register_localhost_without_helper(&provider_registry, &data_dir, &device_key).await;
    }

    match binaries::resolve_verified_native_provider_binary("content-block-graph-provider") {
        Ok(Some(path)) => {
            let block_graph_config = provider::BridgeProviderConfig {
                base_path: data_dir.to_string_lossy().to_string(),
                extra: serde_json::json!({
                    "backend": "kubo_coord"
                }),
                ..Default::default()
            };
            match provider::ProviderBridge::spawn(&path, block_graph_config).await {
                Ok(bridge) => {
                    let block_graph_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "block-graph"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("block-graph", block_graph_provider)
                        .await
                    {
                        tracing::warn!(
                            "Failed to register elastos://block-graph sub-provider: {}",
                            e
                        );
                    }
                    tracing::info!(
                        "content-block-graph-provider capsule from {}",
                        path.display()
                    );
                }
                Err(e) => tracing::warn!("Failed to spawn content-block-graph-provider: {}", e),
            }
        }
        // Not in the 0.8.0 Home profile; `setup --with` adds it.
        Ok(None) => {
            tracing::debug!(
                "content-block-graph-provider binary is not installed; arbitrary DAG repair will fail closed"
            );
        }
        Err(e) => tracing::warn!(
            "Skipping content-block-graph-provider due to verification failure: {}",
            e
        ),
    }

    match binaries::resolve_verified_native_provider_binary("object-provider") {
        Ok(Some(path)) => {
            let object_config = object_provider_bridge_config(&data_dir);
            match provider::ProviderBridge::spawn(&path, object_config).await {
                Ok(bridge) => {
                    let bridge = Arc::new(bridge);
                    let object_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(bridge.clone(), "object"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("object", object_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://object sub-provider: {}", e);
                    }
                    tracing::info!("object-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn object-provider: {}", e),
            }
        }
        Ok(None) => {
            report_missing_home_provider(
                &data_dir,
                "object-provider",
                "Library object operations will fail closed",
            );
        }
        Err(e) => tracing::warn!(
            "Skipping object-provider due to verification failure: {}",
            e
        ),
    }

    match binaries::resolve_verified_native_provider_binary("webspace-provider") {
        Ok(Some(path)) => {
            let webspace_config = provider::BridgeProviderConfig {
                base_path: data_dir.to_string_lossy().to_string(),
                read_only: false,
                ..Default::default()
            };
            match provider::ProviderBridge::spawn(&path, webspace_config).await {
                Ok(bridge) => {
                    let provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "webspace"),
                    );
                    provider_registry.register(provider).await;
                    tracing::info!("webspace-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn webspace-provider: {}", e),
            }
        }
        Ok(None) => {
            report_missing_home_provider(
                &data_dir,
                "webspace-provider",
                "WebSpace roots will fail closed",
            );
        }
        Err(e) => tracing::warn!(
            "Skipping webspace-provider due to verification failure: {}",
            e
        ),
    }

    match binaries::resolve_verified_native_provider_binary(MEDIA_PROVIDER_ID) {
        Ok(Some(path)) => match media_provider_bridge_config(&data_dir) {
            Ok(Some(media_config)) => {
                match provider::ProviderBridge::spawn(&path, media_config).await {
                    Ok(bridge) => {
                        let bridge = Arc::new(bridge);
                        match start_media_provider(
                            &provider_registry,
                            bridge,
                            MEDIA_PROVIDER_STATUS_TIMEOUT,
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::info!("media-provider capsule from verified install")
                            }
                            Err(_) => {
                                tracing::warn!("Skipping media-provider because startup failed")
                            }
                        }
                    }
                    Err(_) => tracing::warn!("Skipping media-provider because startup failed"),
                }
            }
            Ok(None) => tracing::info!("media-provider is installed but unconfigured"),
            Err(_) => tracing::warn!("Skipping media-provider due to invalid private config"),
        },
        // Protected content ships after 0.8.0; its providers install with `setup --with`.
        Ok(None) => tracing::debug!(
            "media-provider binary is not installed; protected-content media sessions will fail closed"
        ),
        Err(_) => tracing::warn!("Skipping media-provider due to verification failure"),
    }

    match binaries::resolve_verified_native_provider_binary("ipfs-provider") {
        Ok(Some(path)) => {
            match register_ipfs_provider_plane_with_role(
                &provider_registry,
                &path,
                ipfs_role,
                &data_dir,
            )
            .await
            {
                Ok(()) => tracing::info!("ipfs-provider capsule from {}", path.display()),
                Err(e) => tracing::warn!("ipfs-provider unavailable: {}", e),
            }
        }
        Ok(None) => {
            tracing::warn!(
                "ipfs-provider binary is not installed; elastos://content publish/fetch will fail closed"
            );
        }
        Err(e) => tracing::warn!("Skipping ipfs-provider due to verification failure: {}", e),
    }

    // Admitted model startup reuses the registered native IPFS verifier.
    match binaries::resolve_verified_native_provider_binary("model-provider") {
        Ok(Some(path)) => {
            match model_provider_startup_config(&data_dir, &provider_registry).await {
                Ok((mut model_config, worker)) => {
                    // Refuse before any spawn when this OS has no confinement backend.
                    let confinement = model_provider_confinement(std::env::consts::OS);
                    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                    let bridge_result: Result<
                        (provider::ProviderBridge, Option<()>, _, Option<()>),
                        provider::bridge::BridgeError,
                    > = match confinement {
                        Ok(()) => unreachable!(
                            "model_provider_confinement refuses every OS without a confinement backend"
                        ),
                        Err(refusal) => Err(refusal),
                    };
                    #[cfg(target_os = "macos")]
                    let bridge_result = match confinement {
                        Ok(()) => {
                            let root = Path::new(&model_config.base_path);
                            let bundle = api::model_provider_engine_bundle(root).map_err(|_| {
                                provider::bridge::BridgeError::InitFailed(
                                    "model engine confinement unavailable".into(),
                                )
                            });
                            match bundle {
                                Ok(bundle) => provider::ProviderBridge::spawn_confined_model_with_engine_bundle(
                                    &path,
                                    model_config.clone(),
                                    bundle.as_deref(),
                                )
                                .await
                                .map(|(bridge, sockets, vacant, config, listener)| {
                                    (bridge, Some((sockets, vacant)), config, Some(listener))
                                }),
                                Err(refusal) => Err(refusal),
                            }
                        }
                        Err(refusal) => Err(refusal),
                    };
                    #[cfg(target_os = "linux")]
                    let bridge_result = match confinement {
                        Ok(()) => provider::ProviderBridge::spawn_confined_model_linux(
                            &path,
                            model_config.clone(),
                        )
                        .await
                        .map(|(bridge, sockets, vacant, config)| {
                            (bridge, Some((sockets, vacant)), config, None::<()>)
                        }),
                        Err(refusal) => Err(refusal),
                    };
                    match bridge_result {
                        Ok((bridge, local_sockets, confined_config, hosted_listener)) => {
                            model_config = confined_config;
                            #[cfg(any(target_os = "macos", target_os = "linux"))]
                            if let Some((sockets, vacant)) = local_sockets {
                                provider_registry
                                    .set_local_model_sockets(sockets, vacant)
                                    .await;
                                #[cfg(target_os = "macos")]
                                if let Some(socket) =
                                    model_config.extra["runtime_hosted_socket"].as_str()
                                {
                                    provider_registry
                                        .set_hosted_model_socket(socket.to_owned())
                                        .await;
                                }
                            }
                            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                            let _ = local_sockets;
                            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
                            let _ = model_config;
                            #[cfg(not(target_os = "macos"))]
                            let _ = hosted_listener;
                            let bridge = Arc::new(bridge);
                            #[cfg(target_os = "macos")]
                            if let Some(listener) = hosted_listener {
                                if let Err(error) = api::model_provider_egress::start(
                                    listener,
                                    bridge.clone(),
                                    data_dir.clone(),
                                ) {
                                    tracing::warn!(%error, "model hosted egress broker unavailable");
                                }
                            }
                            let startup = async {
                                #[cfg(unix)]
                                api::settle_pending_model_startup(
                                    &data_dir,
                                    &bridge,
                                    &model_config,
                                    worker.as_ref(),
                                )
                                .await?;
                                start_model_provider(
                                    &provider_registry,
                                    bridge.clone(),
                                    MODEL_PROVIDER_STATUS_TIMEOUT,
                                )
                                .await
                            }
                            .await;
                            match startup {
                                Ok(()) => {
                                    #[cfg(unix)]
                                    if let Err(error) = api::complete_admitted_model_startup(
                                        &data_dir,
                                        &provider_registry,
                                        worker.as_ref(),
                                    )
                                    .await
                                    {
                                        tracing::warn!(%error, "model startup activation receipt pending");
                                    }
                                    tracing::info!("model-provider capsule from {}", path.display())
                                }
                                Err(_) => {
                                    let _ = bridge.shutdown().await;
                                    tracing::warn!("Skipping model-provider because startup failed")
                                }
                            }
                        }
                        Err(provider::bridge::BridgeError::InitFailed(reason)) => {
                            tracing::warn!("Skipping model-provider: {}", reason)
                        }
                        Err(_) => tracing::warn!("Skipping model-provider because startup failed"),
                    }
                    drop(worker);
                }
                Err(_) => {
                    tracing::warn!(
                        "Skipping model-provider due to invalid private model configuration"
                    )
                }
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("Skipping model-provider due to verification failure: {}", e),
    }

    match binaries::resolve_verified_native_provider_binary("chain-provider") {
        Ok(Some(path)) => {
            let protected_chain_config = chain_provider_protected_startup_config(
                &data_dir,
                &protected_content_runtime_issuer,
            );
            let generic_chain_config = chain_provider_bridge_config_without_protected_network(
                &protected_content_runtime_issuer,
            );
            match provider::ProviderBridge::spawn(&path, generic_chain_config).await {
                Ok(bridge) => {
                    let bridge = Arc::new(bridge);
                    let mut transport_ready = true;
                    if let Some(config) = protected_chain_config {
                        match bridge
                            .request(provider::bridge::ProviderRequest::Init { config })
                            .await
                        {
                            Ok(provider::bridge::ProviderResponse::Ok { .. }) => {}
                            Ok(provider::bridge::ProviderResponse::Error { .. }) => {
                                tracing::warn!(
                                    "Protected-content Chain configuration was rejected; protected operations remain unavailable"
                                );
                            }
                            Err(_) => {
                                tracing::warn!(
                                    "Chain provider transport failed while applying protected-content configuration"
                                );
                                let _ = bridge.shutdown().await;
                                transport_ready = false;
                            }
                        }
                    }
                    if transport_ready {
                        let chain_provider: Arc<dyn provider::Provider> =
                            Arc::new(provider::CapsuleProvider::with_scheme(bridge, "chain"));
                        if let Err(e) = provider_registry
                            .register_sub_provider("chain", chain_provider)
                            .await
                        {
                            tracing::warn!(
                                "Failed to register elastos://chain sub-provider: {}",
                                e
                            );
                        }
                        tracing::info!("chain-provider capsule from {}", path.display());
                    }
                }
                Err(e) => tracing::warn!("Failed to spawn chain-provider: {}", e),
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("Skipping chain-provider due to verification failure: {}", e),
    }

    match binaries::resolve_verified_native_provider_binary("net-provider") {
        Ok(Some(path)) => match provider::ProviderBridge::spawn(&path, Default::default()).await {
            Ok(bridge) => {
                let net_provider: Arc<dyn provider::Provider> = Arc::new(
                    provider::CapsuleProvider::with_scheme(Arc::new(bridge), "net"),
                );
                if let Err(e) = provider_registry
                    .register_sub_provider("net", net_provider)
                    .await
                {
                    tracing::warn!("Failed to register elastos://net sub-provider: {}", e);
                }
                tracing::info!("net-provider capsule from {}", path.display());
            }
            Err(e) => tracing::warn!("Failed to spawn net-provider: {}", e),
        },
        Ok(None) => {}
        Err(e) => tracing::warn!("Skipping net-provider due to verification failure: {}", e),
    }

    // Retained Browser helpers from an earlier release stay stopped where
    // Browser is unavailable.
    let browser_available =
        elastos_server::setup::browser_available(&elastos_server::setup::detect_platform());
    if let Some(local_exit_config) = browser_available
        .then(|| browser_local_exit_config_from_env(&data_dir))
        .flatten()
    {
        if let Some(path) = crate::find_installed_provider_binary("browser-local-exit") {
            if let Err(e) = verify_provider_binary("browser-local-exit", &path) {
                tracing::warn!(
                    "Skipping browser-local-exit due to verification failure: {}",
                    e
                );
            } else {
                match spawn_browser_local_exit(&path, &local_exit_config) {
                    Ok(child) => {
                        tracing::info!("browser-local-exit helper from {}", path.display());
                        managed_host_processes.push(api::server::HostHelperProcess {
                            name: "browser-local-exit",
                            child,
                        });
                    }
                    Err(e) => tracing::warn!("Failed to spawn browser-local-exit: {}", e),
                }
            }
        } else {
            tracing::warn!(
                "Browser local Exit configured but browser-local-exit binary is not installed"
            );
        }
    }

    match binaries::resolve_verified_native_provider_binary("exit-provider") {
        Ok(Some(path)) => {
            let exit_config = provider::BridgeProviderConfig {
                extra: exit_provider_config_from_env(&data_dir).unwrap_or(serde_json::Value::Null),
                ..Default::default()
            };
            match provider::ProviderBridge::spawn(&path, exit_config).await {
                Ok(bridge) => {
                    let exit_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "exit"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("exit", exit_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://exit sub-provider: {}", e);
                    }
                    tracing::info!("exit-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn exit-provider: {}", e),
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("Skipping exit-provider due to verification failure: {}", e),
    }

    let browser_engine_adapter = if browser_available {
        binaries::resolve_verified_native_provider_binary("browser-engine-adapter")
    } else {
        Ok(None)
    };
    match browser_engine_adapter {
        Ok(Some(path)) => {
            let browser_engine_config = provider::BridgeProviderConfig {
                extra: browser_engine_adapter_config_from_env(&data_dir)
                    .unwrap_or(serde_json::Value::Null),
                ..Default::default()
            };
            match provider::ProviderBridge::spawn_with_owned_helpers(&path, browser_engine_config)
                .await
            {
                Ok(bridge) => {
                    let bridge = Arc::new(bridge);
                    match start_browser_engine_provider(
                        &provider_registry,
                        bridge,
                        BROWSER_ENGINE_PROVIDER_STATUS_TIMEOUT,
                    )
                    .await
                    {
                        Ok(()) => {
                            tracing::info!("browser-engine-adapter capsule from {}", path.display())
                        }
                        Err(e) => {
                            tracing::warn!("Failed to start browser-engine-adapter: {}", e)
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to spawn browser-engine-adapter: {}", e),
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!(
            "Skipping browser-engine-adapter due to verification failure: {}",
            e
        ),
    }

    if let Err(err) = start_wallet_provider(
        &data_dir,
        &provider_registry,
        WALLET_PROVIDER_STATUS_TIMEOUT,
    )
    .await
    {
        tracing::warn!("Skipping wallet-provider: {}", err);
    }

    if let Some(path) = crate::find_installed_provider_binary("drm-provider") {
        if let Err(e) = verify_provider_binary("drm-provider", &path) {
            tracing::warn!("Skipping drm-provider due to verification failure: {}", e);
        } else {
            match provider::ProviderBridge::spawn(
                &checked_native_provider(&path),
                Default::default(),
            )
            .await
            {
                Ok(bridge) => {
                    let drm_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "drm"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("drm", drm_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://drm sub-provider: {}", e);
                    }
                    tracing::info!("drm-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn drm-provider: {}", e),
            }
        }
    }

    if let Some(path) = crate::find_installed_provider_binary("rights-provider") {
        if let Err(e) = verify_provider_binary("rights-provider", &path) {
            tracing::warn!(
                "Skipping rights-provider due to verification failure: {}",
                e
            );
        } else {
            match provider::ProviderBridge::spawn(
                &checked_native_provider(&path),
                Default::default(),
            )
            .await
            {
                Ok(bridge) => {
                    let rights_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "rights"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("rights", rights_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://rights sub-provider: {}", e);
                    }
                    tracing::info!("rights-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn rights-provider: {}", e),
            }
        }
    }

    if let Some(path) = crate::find_installed_provider_binary("key-provider") {
        if let Err(e) = verify_provider_binary("key-provider", &path) {
            tracing::warn!("Skipping key-provider due to verification failure: {}", e);
        } else {
            match provider::ProviderBridge::spawn(
                &checked_native_provider(&path),
                Default::default(),
            )
            .await
            {
                Ok(bridge) => {
                    let key_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "key"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("key", key_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://key sub-provider: {}", e);
                    }
                    tracing::info!("key-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn key-provider: {}", e),
            }
        }
    }

    if let Some(path) = crate::find_installed_provider_binary("decrypt-provider") {
        if let Err(e) = verify_provider_binary("decrypt-provider", &path) {
            tracing::warn!(
                "Skipping decrypt-provider due to verification failure: {}",
                e
            );
        } else {
            match provider::ProviderBridge::spawn(
                &checked_native_provider(&path),
                Default::default(),
            )
            .await
            {
                Ok(bridge) => {
                    let decrypt_provider: Arc<dyn provider::Provider> = Arc::new(
                        provider::CapsuleProvider::with_scheme(Arc::new(bridge), "decrypt"),
                    );
                    if let Err(e) = provider_registry
                        .register_sub_provider("decrypt", decrypt_provider)
                        .await
                    {
                        tracing::warn!("Failed to register elastos://decrypt sub-provider: {}", e);
                    }
                    tracing::info!("decrypt-provider capsule from {}", path.display());
                }
                Err(e) => tracing::warn!("Failed to spawn decrypt-provider: {}", e),
            }
        }
    }

    if let Some(path) = crate::find_installed_provider_binary("protected-content-decrypt-provider")
    {
        if let Err(e) = verify_provider_binary("protected-content-decrypt-provider", &path) {
            tracing::warn!(
                "Skipping protected-content-decrypt-provider due to verification failure: {}",
                e
            );
        } else if let Err(e) =
            elastos_server::protected_content_runtime::register_protected_content_decrypt_provider(
                &provider_registry,
                &path,
                protected_content_runtime_issuer,
            )
            .await
        {
            tracing::warn!(
                "Failed to register Runtime-only protected-content decrypt provider: {}",
                e
            );
        } else {
            tracing::info!(
                "protected-content-decrypt-provider registered on Runtime-only target protected-content-decrypt; provisional decrypt-provider remains on elastos://decrypt"
            );
            elastos_server::protected_content_runtime::reconcile_runtime_custody_viewers_after_decrypt_boot(
                &data_dir,
                provider_registry.clone(),
            )
            .await;
        }
    } else {
        tracing::debug!(
            "protected-content-decrypt-provider binary is not installed; protected-content open and play will fail closed"
        );
    }

    if let Some(path) = crate::find_installed_provider_binary("protected-content-protect-provider")
    {
        if let Err(e) = verify_provider_binary("protected-content-protect-provider", &path) {
            tracing::warn!(
                "Skipping protected-content-protect-provider due to verification failure: {}",
                e
            );
        } else if let Err(e) = elastos_server::protected_content_runtime::register_protect_provider(
            &provider_registry,
            &path,
        )
        .await
        {
            tracing::warn!("Failed to register Runtime-only protect provider: {}", e);
        } else {
            tracing::info!(
                "protected-content-protect-provider capsule from {}",
                path.display()
            );
        }
    } else {
        tracing::debug!(
            "protected-content-protect-provider binary is not installed; protected-content mint will fail closed"
        );
    }

    if let Some(path) = crate::find_installed_provider_binary("custody-provider") {
        if let Err(e) = verify_provider_binary("custody-provider", &path) {
            tracing::warn!(
                "Skipping custody-provider due to verification failure: {}",
                e
            );
        } else if let Err(e) =
            elastos_server::protected_content_runtime::register_inactive_custody_provider(
                &provider_registry,
                &path,
                &data_dir,
            )
            .await
        {
            tracing::warn!(
                "Failed to register inactive Runtime-only custody provider: {}",
                e
            );
        } else {
            tracing::info!(
                "custody-provider registered as inactive Runtime custody route; provisional key-provider remains the product path"
            );
        }
    } else {
        report_missing_home_provider(
            &data_dir,
            "custody-provider",
            "the inactive Runtime custody route will be unavailable",
        );
    }

    // Peers are served only CIDs an active publication lists: bring that
    // index in line with the publish records before Carrier answers anyone.
    {
        let data_dir = data_dir.clone();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            elastos_server::library::reconcile_published_cids(&data_dir)
        })
        .await
        {
            tracing::warn!("Published CID index reconcile failed: {}", e);
        }
    }

    // Built-in Carrier node — ALWAYS starts, not conditional on spawn_host_providers.
    // Carrier is fundamental infrastructure: gossip, content, identity.
    // Identity is DID (derived from device_key), not raw device_key.
    let (carrier_signing_key, carrier_did) = elastos_identity::derive_did(&device_key);
    let mut collaboration_carrier_provider: Option<Arc<dyn provider::Provider>> = None;
    {
        match start_carrier_plane(
            &provider_registry,
            &carrier_signing_key,
            &carrier_did,
            &data_dir,
            carrier_bind_addr,
            &collaboration_configuration.community_bootstrap_node_ids(),
        )
        .await
        {
            Ok(carrier_node) => {
                let gossip_provider: Arc<dyn provider::Provider> =
                    Arc::new(elastos_server::carrier::CarrierGossipProvider::new(
                        carrier_node.gossip_state.clone(),
                    ));
                collaboration_carrier_provider = Some(gossip_provider.clone());
                if let Err(e) = provider_registry
                    .register_sub_provider("peer", gossip_provider)
                    .await
                {
                    tracing::warn!("Failed to register Carrier gossip provider: {}", e);
                }
                if !external_availability_registered {
                    let availability_provider = Arc::new(
                            elastos_server::carrier::CarrierAvailabilityProvider::with_provider_registry_data_dir_and_peer_attestation_exchange_config(
                            carrier_node.gossip_state.clone(),
                            Arc::downgrade(&provider_registry),
                            data_dir.clone(),
                            carrier_peer_attestation_exchange_config_from_env(),
                        ));
                    availability_provider
                        .restore_persisted_local_holder_announcements()
                        .await;
                    if let Err(e) = provider_registry
                        .register_sub_provider("availability", availability_provider)
                        .await
                    {
                        tracing::warn!("Failed to register Carrier availability provider: {}", e);
                    }
                    if let Some(content) = content_plane.as_ref() {
                        content.restore_complete_local_objects().await;
                    }
                }
                carrier_service = Some(elastos_server::carrier::CarrierRuntimeService::new(
                    carrier_node,
                ));
                tracing::info!("Carrier node online (P2P + gossip)");
            }
            Err(e) if carrier_bind_addr.is_some() => {
                return Err(e).context("Configured Carrier listener could not start");
            }
            Err(e) => {
                tracing::warn!("Carrier node failed: {:#}", e);
            }
        }
    }

    let collaboration_service =
        elastos_server::collaboration_startup::start_collaboration_runtime_service(
            &data_dir,
            carrier_signing_key,
            collaboration_configuration,
            collaboration_carrier_provider,
            provider_registry.clone(),
            Some(capability_manager.clone()),
        )
        .await?;
    if let (Some(collaboration), Some(carrier)) =
        (collaboration_service.as_ref(), carrier_service.as_ref())
    {
        collaboration.configure_browser_exit_carrier(carrier).await;
    }
    let mut collaboration_context = collaboration_service
        .as_ref()
        .map(|service| service.gateway_context())
        .unwrap_or_default();
    collaboration_context.capability_manager = Some(capability_manager.clone());
    collaboration_context.carrier_endpoint = carrier_service
        .as_ref()
        .and_then(|service| service.endpoint());

    maybe_spawn_content_repair_scheduler(provider_registry.clone());

    let namespace_path = data_dir.join("namespaces");
    std::fs::create_dir_all(&namespace_path).ok();
    let resolver_config = content::ResolverConfig {
        // No ambient public-web fetch in the default trusted server path.
        ipfs_gateways: Vec::new(),
        ..content::ResolverConfig::default()
    };
    let content_resolver = Arc::new(content::ContentResolver::new(
        resolver_config,
        audit_log.clone(),
        Arc::new(fetcher::LoopbackIpfsGatewayFetcher::new()),
    ));
    let namespace_store = Arc::new(namespace::NamespaceStore::new(
        namespace_path,
        content_resolver,
        audit_log.clone(),
    ));

    let identity_state = match elastos_identity::IdentityManager::new(data_dir.clone()) {
        Ok(manager) => {
            tracing::info!("Identity manager initialized (dynamic RP)");
            Some(api::handlers::identity::IdentityState {
                manager: Arc::new(tokio::sync::Mutex::new(manager)),
                session_registry: session_registry.clone(),
                audit_log: Some(audit_log.clone()),
                data_dir: data_dir.clone(),
            })
        }
        Err(e) => {
            tracing::warn!("Identity manager disabled: {}", e);
            None
        }
    };

    let shell_cid = crate::find_installed_provider_binary("shell").and_then(|path| {
        std::fs::read(&path).ok().map(|bytes| {
            let cid = format!(
                "sha256:{}",
                hex::encode(elastos_runtime::signature::hash_content(&bytes))
            );
            tracing::info!("shell capsule {} from {}", cid, path.display());
            cid
        })
    });

    Ok(ServerInfrastructure {
        audit_log,
        session_registry,
        capability_manager,
        capability_store,
        pending_store,
        provider_registry,
        namespace_store,
        identity_state,
        tls_config,
        provider_cid,
        shell_cid,
        host_helpers: managed_host_processes,
        carrier_service,
        collaboration_context,
        collaboration_service,
    })
}

fn spawn_browser_local_exit(path: &Path, config: &serde_json::Value) -> anyhow::Result<Child> {
    let relay_path = browser_local_exit_relay_path(config)?;
    if config
        .get("replace_existing_socket")
        .and_then(|value| value.as_bool())
        == Some(true)
    {
        remove_existing_browser_local_exit_socket(&relay_path)?;
    }
    // `stdin` is the helper's parent-liveness channel, not a data channel: we
    // hold the write end open for as long as this process lives, so the helper
    // reads EOF and reaps itself however we exit. `HostHelperProcess::drop` only
    // covers graceful shutdown — SIGKILL, an abort on panic, and the installed
    // binary supersession watch's `process::exit` all skip it, and each of those
    // used to strand a helper holding the relay socket.
    let mut child = Command::new(path)
        .env(
            "ELASTOS_BROWSER_LOCAL_EXIT_CONFIG",
            serde_json::to_string(config)?,
        )
        .env("ELASTOS_BROWSER_LOCAL_EXIT_PARENT_EOF", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            anyhow::bail!("browser-local-exit exited during startup with {status}");
        }
        match browser_local_exit_socket_ready(&relay_path) {
            Ok(true) => return Ok(child),
            Ok(false) => {}
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(err);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    anyhow::bail!("browser-local-exit did not create relay socket");
}

fn browser_local_exit_socket_ready(path: &Path) -> anyhow::Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            anyhow::bail!(
                "failed to inspect browser-local-exit relay socket {}: {}",
                path.display(),
                err
            )
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            anyhow::bail!(
                "browser-local-exit relay_ipc_path is not a Unix socket: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "unsupported on this platform",
        )
        .into());
    }

    #[cfg(unix)]
    Ok(true)
}

fn browser_local_exit_relay_path(config: &serde_json::Value) -> anyhow::Result<PathBuf> {
    let relay_path = config
        .get("relay_ipc_path")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("browser-local-exit config missing relay_ipc_path"))?;
    if relay_path.is_empty()
        || relay_path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'\0')
    {
        anyhow::bail!(
            "browser-local-exit relay_ipc_path must be an absolute path without whitespace"
        );
    }
    let path = PathBuf::from(relay_path);
    if !path.is_absolute() {
        anyhow::bail!(
            "browser-local-exit relay_ipc_path must be an absolute path without whitespace"
        );
    }
    Ok(path)
}

fn remove_existing_browser_local_exit_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            anyhow::bail!(
                "failed to inspect existing browser-local-exit relay socket {}: {}",
                path.display(),
                err
            )
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() {
            anyhow::bail!(
                "refusing to remove browser-local-exit relay_ipc_path because it is not a Unix socket: {}",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        anyhow::bail!(
            "browser-local-exit replace_existing_socket is only supported for Unix socket paths"
        );
    }

    // Unlinking a socket a live helper is still listening on does not stop that
    // helper — it keeps serving an unreachable, unlinked socket forever. Doing it
    // blindly on every launch is how helpers piled up one per launch, all bound to
    // the same path. Give an incumbent a moment to reap itself (the parent-EOF
    // watch makes that prompt) before deciding the path is genuinely abandoned.
    #[cfg(unix)]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        while browser_local_exit_socket_has_listener(path) {
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "browser-local-exit relay socket {} is still served by a live helper; \
                     stop the ElastOS host that owns it before starting another",
                    path.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(unix)]
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        // The incumbent reaped itself and removed its own socket.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(anyhow::anyhow!(
            "failed to remove existing browser-local-exit relay socket {}: {}",
            path.display(),
            err
        )),
    }
}

/// Whether anything is still accepting on `path`, distinguishing a live helper
/// from a socket file left behind by one that is already gone.
#[cfg(unix)]
fn browser_local_exit_socket_has_listener(path: &Path) -> bool {
    use std::os::unix::net::UnixStream;

    match UnixStream::connect(path) {
        Ok(stream) => {
            // Connected without sending a relay-open handshake; drop it immediately.
            let _ = stream.shutdown(std::net::Shutdown::Both);
            true
        }
        // ECONNREFUSED means the socket file outlived its listener.
        Err(_) => false,
    }
}

pub(crate) fn availability_provider_config_from_env() -> Option<serde_json::Value> {
    if let Ok(raw) = std::env::var("ELASTOS_AVAILABILITY_PROVIDER_CONFIG") {
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => return Some(value),
            Err(err) => {
                tracing::warn!(
                    "Ignoring invalid ELASTOS_AVAILABILITY_PROVIDER_CONFIG JSON: {}",
                    err
                );
                return None;
            }
        }
    }

    let ensure_url = std::env::var("ELASTOS_AVAILABILITY_ENSURE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let mut target = serde_json::json!({
        "id": std::env::var("ELASTOS_AVAILABILITY_PROVIDER_ID")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "configured-supernode".to_string()),
        "ensure_url": ensure_url,
    });
    if let Ok(value) = std::env::var("ELASTOS_AVAILABILITY_AUTHORIZATION") {
        let value = value.trim();
        if !value.is_empty() {
            target["authorization"] = serde_json::Value::String(value.to_string());
        }
    }

    Some(serde_json::json!({
        "targets": [target]
    }))
}

fn carrier_peer_attestation_exchange_config_from_env() -> Option<serde_json::Value> {
    if let Ok(raw) = std::env::var("ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_CONFIG") {
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => return Some(value),
            Err(err) => {
                tracing::warn!(
                    "Ignoring invalid ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_CONFIG JSON: {}",
                    err
                );
                return None;
            }
        }
    }

    let url = std::env::var("ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let mut config = serde_json::json!({ "url": url });
    if let Ok(value) = std::env::var("ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_AUTHORIZATION") {
        let value = value.trim();
        if !value.is_empty() {
            config["authorization"] = serde_json::Value::String(value.to_string());
        }
    }
    if let Ok(value) = std::env::var("ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_TIMEOUT_SECS") {
        if let Ok(timeout_secs) = value.trim().parse::<u64>() {
            config["timeout_secs"] = serde_json::Value::from(timeout_secs);
        }
    }
    Some(config)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContentRepairSchedulerConfig {
    interval_secs: u64,
    limit: u64,
    max_attempts: u64,
    failure_budget: u64,
    include_healthy_check: bool,
}

fn content_repair_scheduler_config_from_env() -> Option<ContentRepairSchedulerConfig> {
    if !env_flag_enabled(CONTENT_REPAIR_SCHEDULER_ENV) {
        return None;
    }
    Some(ContentRepairSchedulerConfig {
        interval_secs: env_u64(
            CONTENT_REPAIR_SCHEDULER_INTERVAL_ENV,
            CONTENT_REPAIR_SCHEDULER_DEFAULT_INTERVAL_SECS,
        )
        .max(CONTENT_REPAIR_SCHEDULER_MIN_INTERVAL_SECS),
        limit: env_u64(
            CONTENT_REPAIR_SCHEDULER_LIMIT_ENV,
            CONTENT_REPAIR_SCHEDULER_DEFAULT_LIMIT,
        )
        .clamp(1, 100),
        max_attempts: env_u64(
            CONTENT_REPAIR_SCHEDULER_MAX_ATTEMPTS_ENV,
            CONTENT_REPAIR_SCHEDULER_DEFAULT_MAX_ATTEMPTS,
        )
        .clamp(1, 25),
        failure_budget: env_u64(
            CONTENT_REPAIR_SCHEDULER_FAILURE_BUDGET_ENV,
            CONTENT_REPAIR_SCHEDULER_DEFAULT_FAILURE_BUDGET,
        )
        .clamp(1, 100),
        include_healthy_check: env_flag_enabled(CONTENT_REPAIR_SCHEDULER_INCLUDE_HEALTHY_ENV),
    })
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn maybe_spawn_content_repair_scheduler(registry: Arc<provider::ProviderRegistry>) {
    let Some(config) = content_repair_scheduler_config_from_env() else {
        tracing::debug!(
            "{} is disabled; content repair worker remains manual/operator-triggered",
            CONTENT_REPAIR_SCHEDULER_ENV
        );
        return;
    };
    tracing::info!(
        "content repair scheduler enabled: interval={}s limit={} max_attempts={} failure_budget={} include_healthy_check={}",
        config.interval_secs,
        config.limit,
        config.max_attempts,
        config.failure_budget,
        config.include_healthy_check,
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match invoke_content_repair_worker(&registry, config).await {
                Ok(response) => {
                    let data = response.get("data").unwrap_or(&response);
                    tracing::debug!(
                        "content repair scheduler run completed: checked={} repaired={} failed={} skipped={}",
                        data.get("checked")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(0),
                        data.get("repaired")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(0),
                        data.get("failed")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(0),
                        data.get("skipped")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(0),
                    );
                }
                Err(err) => {
                    tracing::warn!("content repair scheduler run failed: {}", err);
                }
            }
        }
    });
}

async fn invoke_content_repair_worker(
    registry: &provider::ProviderRegistry,
    config: ContentRepairSchedulerConfig,
) -> Result<serde_json::Value, provider::ProviderError> {
    registry
        .invoke_provider(ProviderInvocation {
            source: "content-provider".to_string(),
            target: "content".to_string(),
            op: "repair_worker".to_string(),
            request: serde_json::json!({
                "op": "repair_worker",
                "force": false,
                "include_healthy_check": config.include_healthy_check,
                "limit": config.limit,
                "max_attempts": config.max_attempts,
                "failure_budget": config.failure_budget,
            }),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: ProviderInvocationTransport::Local,
        })
        .await
}

fn exit_provider_config_from_env(data_dir: &std::path::Path) -> Option<serde_json::Value> {
    provider_config_from_env_or_file(
        data_dir,
        "ELASTOS_EXIT_PROVIDER_CONFIG",
        "exit-provider.json",
    )
}

fn browser_engine_adapter_config_from_env(data_dir: &std::path::Path) -> Option<serde_json::Value> {
    provider_config_from_env_or_file(
        data_dir,
        "ELASTOS_BROWSER_ENGINE_ADAPTER_CONFIG",
        "browser-engine-adapter.json",
    )
}

fn browser_local_exit_config_from_env(data_dir: &std::path::Path) -> Option<serde_json::Value> {
    provider_config_from_env_or_file(
        data_dir,
        "ELASTOS_BROWSER_LOCAL_EXIT_CONFIG",
        "browser-local-exit.json",
    )
}

fn provider_config_from_env_or_file(
    data_dir: &std::path::Path,
    env_name: &str,
    file_name: &str,
) -> Option<serde_json::Value> {
    if let Ok(raw) = std::env::var(env_name) {
        return match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(value) => Some(value),
            Err(err) => {
                tracing::warn!("Ignoring invalid {} JSON: {}", env_name, err);
                None
            }
        };
    }
    let path = data_dir.join("config").join(file_name);
    let raw = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(value) => Some(value),
        Err(err) => {
            tracing::warn!(
                "Ignoring invalid provider config {}: {}",
                path.display(),
                err
            );
            None
        }
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    #[test]
    fn configured_carrier_listener_is_optional_and_strict() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            super::configured_carrier_bind_addr(dir.path()).unwrap(),
            None
        );
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "dev_mode = true\n").unwrap();
        assert_eq!(
            super::configured_carrier_bind_addr(dir.path()).unwrap(),
            None
        );
        std::fs::write(&path, r#"carrier_bind_addr = "127.0.0.1:61967""#).unwrap();
        assert_eq!(
            super::configured_carrier_bind_addr(dir.path()).unwrap(),
            Some("127.0.0.1:61967".parse().unwrap())
        );
        for invalid in [
            "carrier_bind_addr = 61967",
            "carrier_bind_addr = \"invalid\"",
            "broken = [",
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(super::configured_carrier_bind_addr(dir.path()).is_err());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), invalid);
        }
    }

    use super::*;
    use crate::localhost_file_migration::{
        hold_localhost_migration_lock, localhost_bringup, localhost_file_key,
        localhost_provider_bridge_config, set_localhost_migration_before_rename,
        set_localhost_migration_before_replace, set_localhost_migration_create_error,
        set_localhost_migration_progress_clock, set_localhost_migration_write_budget,
        set_localhost_migration_write_error, take_localhost_migration_bytes_read,
        take_localhost_migration_opens, LocalhostBringup,
    };
    #[cfg(unix)]
    use std::ffi::CString;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(target_os = "linux")]
    use std::process::Output;
    use std::sync::Mutex;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn absent_optional_home_providers_are_quiet_but_required_provider_warns() {
        use std::io::Write;

        #[derive(Clone)]
        struct WarningWriter(Arc<Mutex<Vec<u8>>>);

        impl Write for WarningWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let temp = TempDir::new().unwrap();
        fs::write(
            temp.path().join("components.json"),
            serde_json::json!({"external": {}, "profiles": {"home": {
                "components": ["ipfs-provider"]
            }}})
            .to_string(),
        )
        .unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let writer = WarningWriter(log.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        for name in ["custody-provider", "object-provider", "webspace-provider"] {
            report_missing_home_provider(temp.path(), name, "unavailable");
        }
        assert!(log.lock().unwrap().is_empty(), "optional providers warned");

        fs::write(
            temp.path().join("components.json"),
            serde_json::json!({"external": {}, "profiles": {"home": {
                "components": ["object-provider"]
            }}})
            .to_string(),
        )
        .unwrap();
        report_missing_home_provider(temp.path(), "object-provider", "unavailable");
        let output = String::from_utf8(log.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("object-provider binary is not installed"),
            "{output}"
        );

        fs::write(temp.path().join("components.json"), "{").unwrap();
        report_missing_home_provider(temp.path(), "custody-provider", "unavailable");
        let output = String::from_utf8(log.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("custody-provider binary is not installed"),
            "{output}"
        );
    }

    fn did_fixture() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        // The signed source names this path. Canonicalize it so the release
        // record and the start-time check name the same file.
        let data_dir = fs::canonicalize(&data_dir).unwrap();
        let bin = data_dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let binary = bin.join("did-provider");
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let source = temp.path().join("did-probe.rs");
            let text = include_str!("../tests/fixtures/did_confined_probe.rs").replace(
                "@@ROOT@@",
                &fs::canonicalize(&data_dir)
                    .unwrap()
                    .join("did")
                    .to_string_lossy(),
            );
            fs::write(&source, text).unwrap();
            let output = Command::new("rustc")
                .args(["--edition", "2021", "-o"])
                .arg(&binary)
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            fs::write(
                &binary,
                format!("#!/bin/sh\ntouch '{}'\n", data_dir.join("marker").display()),
            )
            .unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        }
        use sha2::Digest as _;
        let checksum = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(fs::read(&binary).unwrap()))
        );
        let row = serde_json::json!({"external": {"did-provider": {
            "install_path": "bin/did-provider",
            "provider_runtime": {"role": "provider", "substrate": "native",
                "runtime_abi": "elastos.provider-stdio/v1", "execution": "native-provider",
                "provides": "elastos://did/*"},
            "platforms": {elastos_server::setup::detect_platform(): {
                "checksum": checksum, "install_path": "bin/did-provider"}}
        }}, "capsules": {}, "profiles": {}});
        fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec(&row).unwrap(),
        )
        .unwrap();
        let manifest_dir = data_dir.join("capsules/did-provider");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../capsules/did-provider/capsule.json"),
            manifest_dir.join("capsule.json"),
        )
        .unwrap();
        #[cfg(unix)]
        sign_test_home(&data_dir);
        (temp, data_dir, binary)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn did_probe_failure(data_dir: &Path) -> String {
        let path = data_dir.join("did/probe.error");
        match fs::read_to_string(&path) {
            Ok(report) => {
                let mut lines: Vec<_> = report.lines().rev().take(8).collect();
                lines.reverse();
                format!("probe error (last lines): {}", lines.join("\n"))
            }
            Err(error) => format!("probe error unavailable at {}: {error}", path.display()),
        }
    }

    #[test]
    fn did_caller_has_one_confined_start_and_no_plain_spawn() {
        let source = include_str!("server_infra.rs");
        let start = source.find("async fn start_did_provider(").unwrap();
        let end = source[start..]
            .find("\n    if spawn_host_providers {")
            .unwrap()
            + start;
        let block = &source[start..end];
        assert_eq!(
            block
                .matches("AdmittedProvider::admit(data_dir, \"did-provider\")")
                .count(),
            1
        );
        assert_eq!(block.matches("ProviderBridge::spawn_confined(").count(), 1);
        assert!(!block.contains("ProviderBridge::spawn("));
        assert_eq!(
            block
                .matches("if let Err(err) = start_did_provider(")
                .count(),
            1
        );
        assert!(block.contains("let _ = start_did_provider_for_server("));
        assert_eq!(block.matches("bridge.shutdown().await").count(), 1);
        assert!(block.contains("CapsuleProvider::from_confined(confined, \"did\")"));
    }

    #[tokio::test]
    async fn did_missing_row_leaves_route_and_storage_absent() {
        let temp = TempDir::new().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let fixture = bin.join("did-provider");
        fs::write(
            &fixture,
            format!(
                "#!/bin/sh\ntouch '{}'\n",
                temp.path().join("marker").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755)).unwrap();
        let registry = provider::ProviderRegistry::new();
        assert!(start_did_provider(temp.path(), &registry, &[0u8; 32])
            .await
            .unwrap()
            .is_none());
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_none());
        assert!(!temp.path().join("did").exists());
        assert!(!temp.path().join("marker").exists());
    }

    #[tokio::test]
    async fn did_unadmitted_bytes_leave_route_storage_and_marker_absent() {
        let (_temp, data_dir, binary) = did_fixture();
        fs::write(&binary, b"changed after the row checksum").unwrap();
        let registry = provider::ProviderRegistry::new();
        let error = start_did_provider(&data_dir, &registry, &[0u8; 32])
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("checksum"), "{error}");
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_none());
        assert!(!data_dir.join("did").exists());
        assert!(!data_dir.join("marker").exists());
    }

    /// A Home with no signed release, and the same Home with `dev_mode`,
    /// refuses the DID start. The route, storage root and marker stay absent.
    #[cfg(unix)]
    #[tokio::test]
    async fn did_unsigned_and_dev_mode_homes_refuse_before_anything_is_created() {
        for dev_mode in [false, true] {
            let (_temp, data_dir, _) = did_fixture();
            fs::remove_file(data_dir.join("sources.json")).unwrap();
            if dev_mode {
                fs::write(data_dir.join("config.toml"), "dev_mode = true\n").unwrap();
            }
            let registry = provider::ProviderRegistry::new();
            let error = start_did_provider(&data_dir, &registry, &[7u8; 32])
                .await
                .err()
                .unwrap_or_else(|| panic!("dev_mode={dev_mode} started the DID provider"));
            let message = error.to_string();
            if dev_mode {
                assert!(
                    message.contains("no signed release digest"),
                    "dev_mode={dev_mode}: {message}"
                );
            } else {
                assert!(
                    message.contains("No trusted source configured"),
                    "dev_mode={dev_mode}: {message}"
                );
            }
            assert!(registry
                .registration_for_uri("elastos://did/identity")
                .await
                .is_none());
            assert!(!data_dir.join("did").exists(), "dev_mode={dev_mode}");
            assert!(!data_dir.join("marker").exists(), "dev_mode={dev_mode}");
            assert!(
                !data_dir.join("provider-copies").exists(),
                "dev_mode={dev_mode}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn did_data_dir_symlink_is_refused_before_storage_creation() {
        let (temp, data_dir, _) = did_fixture();
        let linked_data_dir = temp.path().join("linked-data");
        std::os::unix::fs::symlink(&data_dir, &linked_data_dir).unwrap();
        let registry = provider::ProviderRegistry::new();
        let error = match start_did_provider(&linked_data_dir, &registry, &[0u8; 32]).await {
            Err(error) => error,
            Ok(Some(bridge)) => {
                bridge.shutdown().await.unwrap();
                panic!("a symlinked data directory started the DID provider");
            }
            Ok(None) => panic!("the admitted DID provider row was not found"),
        };
        assert_eq!(
            error.to_string(),
            "provider start is refused: the storage root's parent is a symlink"
        );
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_none());
        assert!(!data_dir.join("did").exists());
        assert!(!data_dir.join("marker").exists());
    }

    #[cfg(elastos_unsupported_os_check)]
    #[tokio::test]
    async fn did_os_refusal_keeps_child_and_route_absent() {
        let (_temp, data_dir, _) = did_fixture();
        let registry = provider::ProviderRegistry::new();
        let error = start_did_provider_for_server(&data_dir, &registry, &[0u8; 32])
            .await
            .err()
            .unwrap();
        #[cfg(elastos_unsupported_os_check)]
        assert!(
            error.to_string().contains(
                "this operating system has no confinement, so the provider binary does not start"
            ),
            "{error}"
        );
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_none());
        #[cfg(target_os = "linux")]
        assert!(!data_dir.join("did/child.pid").exists());
        #[cfg(not(target_os = "linux"))]
        assert!(!data_dir.join("marker").exists());
        assert!(!data_dir.join("did").exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn did_linux_admitted_row_answers_and_stays_confined() {
        let (_temp, data_dir, _) = did_fixture();
        let registry = provider::ProviderRegistry::new();
        let bridge = start_did_provider(&data_dir, &registry, &[0u8; 32])
            .await
            .unwrap_or_else(|error| panic!("{error}; {}", did_probe_failure(&data_dir)))
            .unwrap();
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_some());
        let response = registry
            .send_raw("did", &serde_json::json!({"op":"get_did"}))
            .await
            .unwrap();
        assert_eq!(response["data"]["did"], "did:key:zFixture");
        registry
            .send_raw("did", &serde_json::json!({"op":"set_nickname"}))
            .await
            .unwrap();
        assert_eq!(fs::read(data_dir.join("did/nickname")).unwrap(), b"Ada");
        let outside = registry
            .send_raw("did", &serde_json::json!({"op":"probe_outside_write"}))
            .await
            .unwrap();
        assert_eq!(outside["data"]["outside_write_refused"], true);
        assert!(!data_dir.join("outside").exists());
        let pid: libc::pid_t = fs::read_to_string(data_dir.join("did/child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(status.lines().any(|line| line == "Seccomp:\t2"), "{status}");
        assert!(
            status.lines().any(|line| line == "NoNewPrivs:\t1"),
            "{status}"
        );
        bridge.shutdown().await.unwrap();
        assert_eq!(fs::read(data_dir.join("did/shutdown")).unwrap(), b"yes");
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(all(target_os = "macos", not(elastos_unsupported_os_check)))]
    #[tokio::test]
    async fn did_macos_admitted_row_answers_and_stays_confined() {
        let (_temp, data_dir, _) = did_fixture();
        let registry = provider::ProviderRegistry::new();
        let bridge = start_did_provider(&data_dir, &registry, &[0u8; 32])
            .await
            .unwrap_or_else(|error| panic!("{error}; {}", did_probe_failure(&data_dir)))
            .unwrap();
        assert!(registry
            .registration_for_uri("elastos://did/identity")
            .await
            .is_some());
        let answer = registry
            .send_raw("did", &serde_json::json!({"op":"get_did"}))
            .await
            .unwrap();
        assert_eq!(answer["data"]["did"], "did:key:zFixture");
        registry
            .send_raw("did", &serde_json::json!({"op":"set_nickname"}))
            .await
            .unwrap();
        assert_eq!(fs::read(data_dir.join("did/nickname")).unwrap(), b"Ada");
        let outside = registry
            .send_raw("did", &serde_json::json!({"op":"probe_outside_write"}))
            .await
            .unwrap();
        assert_eq!(outside["data"]["outside_write_refused"], true);
        assert!(!data_dir.join("outside").exists());
        bridge.shutdown().await.unwrap();
        assert_eq!(fs::read(data_dir.join("did/shutdown")).unwrap(), b"yes");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn did_registration_collision_sends_shutdown_and_reaps_child() {
        let (_temp, data_dir, _) = did_fixture();
        let registry = provider::ProviderRegistry::new();
        registry
            .register_sub_provider(
                "did",
                Arc::new(DocumentsProvider::new(
                    data_dir.clone(),
                    std::sync::Weak::new(),
                )),
            )
            .await
            .unwrap();
        let error = start_did_provider(&data_dir, &registry, &[0u8; 32])
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("already registered"),
            "{error}; {}",
            did_probe_failure(&data_dir)
        );
        assert_eq!(fs::read(data_dir.join("did/shutdown")).unwrap(), b"yes");
        let pid: libc::pid_t = fs::read_to_string(data_dir.join("did/child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    fn test_provider_bridge(
        status: serde_json::Value,
        response_delay: Duration,
    ) -> (
        Arc<provider::ProviderBridge>,
        tokio::task::JoinHandle<Vec<serde_json::Value>>,
    ) {
        let (bridge_writer, provider_reader) = tokio::io::duplex(4096);
        let (provider_writer, bridge_reader) = tokio::io::duplex(4096);
        let bridge = Arc::new(provider::ProviderBridge::from_io(
            BufReader::new(bridge_reader),
            bridge_writer,
        ));
        let provider = tokio::spawn(async move {
            let mut reader = BufReader::new(provider_reader);
            let mut writer = provider_writer;
            let mut requests = Vec::new();
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            requests.push(serde_json::from_str(line.trim()).unwrap());
            if !response_delay.is_zero() {
                tokio::time::sleep(response_delay).await;
            }
            writer
                .write_all(format!("{}\n", serde_json::to_string(&status).unwrap()).as_bytes())
                .await
                .unwrap();
            writer.flush().await.unwrap();

            line.clear();
            if reader.read_line(&mut line).await.unwrap() > 0 {
                requests.push(serde_json::from_str(line.trim()).unwrap());
                writer.write_all(b"{\"status\":\"ok\"}\n").await.unwrap();
                writer.flush().await.unwrap();
            }
            requests
        });
        (bridge, provider)
    }

    fn provider_status(provider_id: &str, protocol_version: &str) -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "data": {
                "provider": provider_id,
                "protocol_version": protocol_version,
            }
        })
    }

    fn wallet_fixture() -> (TempDir, PathBuf, PathBuf) {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        let bin = data_dir.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(data_dir.join("ElastOS")).unwrap();
        let binary = bin.join("wallet-provider");
        #[cfg(target_os = "linux")]
        {
            let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
            let source = temp.path().join("wallet-probe.rs");
            let text = include_str!("../tests/fixtures/wallet_confined_probe.rs")
                .replace("@@ROOT@@", &wallet_root.to_string_lossy())
                .replace("@@BASE@@", &data_dir.to_string_lossy())
                .replace("@@MARKER@@", &data_dir.join("marker").to_string_lossy())
                .replace("@@PROTOCOL@@", WALLET_PROTOCOL_VERSION);
            fs::write(&source, text).unwrap();
            let output = Command::new("rustc")
                .args(["--edition", "2021", "-o"])
                .arg(&binary)
                .arg(&source)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            fs::write(
                &binary,
                format!("#!/bin/sh\ntouch '{}'\n", data_dir.join("marker").display()),
            )
            .unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        }
        use sha2::Digest as _;
        let checksum = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(fs::read(&binary).unwrap()))
        );
        let row = serde_json::json!({"external": {"wallet-provider": {
            "install_path": "bin/wallet-provider",
            "provider_runtime": {"role": "provider", "substrate": "native",
                "runtime_abi": "elastos.provider-stdio/v1", "execution": "native-provider",
                "provides": "elastos://wallet/meta/status"},
            "platforms": {elastos_server::setup::detect_platform(): {
                "checksum": checksum, "install_path": "bin/wallet-provider"}}
        }}, "capsules": {}, "profiles": {}});
        fs::write(
            data_dir.join("components.json"),
            serde_json::to_vec(&row).unwrap(),
        )
        .unwrap();
        let manifest_dir = data_dir.join("capsules/wallet-provider");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../capsules/wallet-provider/capsule.json"),
            manifest_dir.join("capsule.json"),
        )
        .unwrap();
        #[cfg(unix)]
        sign_test_home(&data_dir);
        (temp, data_dir, binary)
    }

    #[cfg(target_os = "linux")]
    fn wallet_probe_failure(wallet_root: &Path) -> String {
        let path = wallet_root.join("probe.error");
        match fs::read_to_string(&path) {
            Ok(report) => format!("wallet probe panic: {report}"),
            Err(error) => format!(
                "wallet probe report unavailable at {}: {error}",
                path.display()
            ),
        }
    }

    #[test]
    fn wallet_start_path_admits_and_starts_only_confined() {
        let source = include_str!("server_infra.rs");
        let helper_start = source.find("async fn start_wallet_provider_v2(").unwrap();
        let helper_end = source[helper_start..]
            .find("\nasync fn request_model_provider_status(")
            .unwrap()
            + helper_start;
        let caller_start = source
            .find("if let Err(err) = start_wallet_provider(")
            .unwrap();
        let caller_end = source[caller_start..]
            .find(
                "\n    if let Some(path) = crate::find_installed_provider_binary(\"drm-provider\")",
            )
            .unwrap()
            + caller_start;
        let start_path = format!(
            "{}\n{}",
            &source[helper_start..helper_end],
            &source[caller_start..caller_end]
        );
        assert_eq!(
            start_path
                .matches("AdmittedProvider::admit(data_dir, \"wallet-provider\")")
                .count(),
            1
        );
        assert_eq!(
            start_path
                .matches("ProviderBridge::spawn_confined(")
                .count(),
            1
        );
        assert!(!start_path.contains("ProviderBridge::spawn("));
        assert!(!start_path.contains("CapsuleProvider::with_scheme("));
        assert_eq!(
            start_path
                .matches("CapsuleProvider::from_confined(confined, \"wallet\")")
                .count(),
            1
        );
        assert_eq!(start_path.matches("bridge.shutdown().await").count(), 1);
    }

    #[test]
    fn wallet_refusal_texts_and_os_choice_match_runtime_entry() {
        let runtime = include_str!("../../elastos-runtime/src/provider/os_entry.rs");
        let server = include_str!("server_infra.rs");
        let unsupported = runtime
            .split_once("const UNSUPPORTED_OS: &str =")
            .unwrap()
            .1
            .split('"')
            .nth(1)
            .unwrap();
        assert_eq!(WALLET_UNSUPPORTED_OS, unsupported);
        assert!(!runtime.contains("const MACOS_NO_SPAWN"));

        // The three choices must use the Runtime's Linux, macOS and
        // unsupported-OS cfg arms, in that order.
        fn cfg_before(source: &str, position: usize) -> String {
            let start = source[..position].rfind("#[cfg(").unwrap();
            let end = start + source[start..].find(")]").unwrap() + 2;
            source[start..end]
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect()
        }
        let choices = server
            .split_once("fn wallet_confinement_refusal()")
            .unwrap()
            .1
            .split_once("/// Create the wallet storage parent")
            .unwrap()
            .0;
        let dispatches: Vec<_> = runtime
            .match_indices("\nfn dispatch(")
            .map(|(position, _)| position)
            .collect();
        assert_eq!(dispatches.len(), 3);
        let linux = choices.find("        None\n").unwrap();
        let macos = linux + 1 + choices[linux + 1..].find("        None\n").unwrap();
        let unsupported_choice = choices.find("Some(WALLET_UNSUPPORTED_OS)").unwrap();
        for (position, dispatch) in [
            (linux, dispatches[0]),
            (macos, dispatches[1]),
            (unsupported_choice, dispatches[2]),
        ] {
            assert_eq!(cfg_before(choices, position), cfg_before(runtime, dispatch));
        }

        let expected = if cfg!(elastos_unsupported_os_check)
            || !cfg!(any(
                target_os = "macos",
                all(
                    target_os = "linux",
                    any(target_arch = "x86_64", target_arch = "aarch64")
                )
            )) {
            Some(WALLET_UNSUPPORTED_OS)
        } else {
            None
        };
        assert_eq!(wallet_confinement_refusal(), expected);
    }

    #[test]
    fn wallet_parent_preparation_uses_real_effective_uid() {
        let source = include_str!("server_infra.rs");
        let prepare = source
            .split_once("fn prepare_wallet_storage_parent(")
            .unwrap()
            .1
            .split_once("\nasync fn start_wallet_provider(")
            .unwrap()
            .0;
        assert_eq!(
            prepare
                .matches("tighten_wallet_parent(&directory, unsafe { libc::geteuid() })")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn wallet_missing_row_leaves_helper_route_and_storage_absent() {
        let temp = TempDir::new().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let fixture = bin.join("wallet-provider");
        fs::write(
            &fixture,
            format!(
                "#!/bin/sh\ntouch '{}'\n",
                temp.path().join("marker").display()
            ),
        )
        .unwrap();
        fs::set_permissions(&fixture, fs::Permissions::from_mode(0o755)).unwrap();
        let registry = provider::ProviderRegistry::new();
        assert!(
            start_wallet_provider(temp.path(), &registry, Duration::from_secs(1))
                .await
                .unwrap()
                .is_none()
        );
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_none());
        assert!(!temp.path().join("ElastOS/SystemServices/Wallet").exists());
        assert!(!temp.path().join("marker").exists());
    }

    /// A Home with no signed release, and the same Home with `dev_mode`,
    /// refuses the wallet start before its storage is touched. The route,
    /// storage root and marker stay absent.
    #[cfg(unix)]
    #[tokio::test]
    async fn wallet_unsigned_and_dev_mode_homes_refuse_before_anything_is_created() {
        for dev_mode in [false, true] {
            let (_temp, data_dir, _) = wallet_fixture();
            fs::remove_file(data_dir.join("sources.json")).unwrap();
            if dev_mode {
                fs::write(data_dir.join("config.toml"), "dev_mode = true\n").unwrap();
            }
            let registry = provider::ProviderRegistry::new();
            let error = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
                .await
                .err()
                .unwrap_or_else(|| panic!("dev_mode={dev_mode} started the wallet provider"));
            let message = error.to_string();
            if dev_mode {
                assert!(
                    message.contains("no signed release digest"),
                    "dev_mode={dev_mode}: {message}"
                );
            } else {
                assert!(
                    message.contains("No trusted source configured"),
                    "dev_mode={dev_mode}: {message}"
                );
            }
            assert!(registry
                .registration_for_uri("elastos://wallet/status")
                .await
                .is_none());
            assert!(
                !data_dir.join("ElastOS/SystemServices/Wallet").exists(),
                "dev_mode={dev_mode}"
            );
            assert!(!data_dir.join("marker").exists(), "dev_mode={dev_mode}");
            assert!(
                !data_dir.join("provider-copies").exists(),
                "dev_mode={dev_mode}"
            );
        }
    }

    #[tokio::test]
    async fn wallet_unadmitted_bytes_leave_route_storage_and_marker_absent() {
        let (_temp, data_dir, binary) = wallet_fixture();
        fs::write(&binary, b"changed after the row checksum").unwrap();
        let registry = provider::ProviderRegistry::new();
        let error = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("checksum"), "{error}");
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_none());
        assert!(!data_dir.join("ElastOS/SystemServices/Wallet").exists());
        assert!(!data_dir.join("marker").exists());
    }

    #[test]
    fn wallet_storage_parent_is_prepared_and_unsuitable_parent_refused() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(data_dir.join("ElastOS")).unwrap();
        let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
        prepare_wallet_storage_parent(&wallet_root).unwrap();
        let parent = data_dir.join("ElastOS/SystemServices");
        let metadata = fs::symlink_metadata(&parent).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(data_dir.join("ElastOS")).unwrap();
        fs::write(data_dir.join("ElastOS/SystemServices"), b"not a directory").unwrap();
        let error = prepare_wallet_storage_parent(&data_dir.join("ElastOS/SystemServices/Wallet"))
            .unwrap_err();
        assert!(error.to_string().contains("not a directory"), "{error}");
    }

    #[test]
    fn wallet_symlinked_parent_is_refused_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let data_dir = temp.path().join("data");
        fs::create_dir_all(data_dir.join("ElastOS")).unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&target, data_dir.join("ElastOS/SystemServices")).unwrap();

        let result = prepare_wallet_storage_parent(&data_dir.join("ElastOS/SystemServices/Wallet"));
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o777,
            "the symlink target's permissions must stay unchanged"
        );
        assert!(result.is_err(), "a symlinked wallet parent must be refused");
    }

    #[test]
    fn wallet_foreign_parent_owner_is_refused_before_tightening() {
        let temp = TempDir::new().unwrap();
        let parent = temp.path().join("SystemServices");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let directory = fs::File::open(&parent).unwrap();
        // The seam supplies a different effective uid; changing an owner needs root.
        let foreign_effective_uid = unsafe { libc::geteuid() }.wrapping_add(1);

        let result = tighten_wallet_parent(&directory, foreign_effective_uid);
        assert_eq!(
            fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o777,
            "a refused parent's permissions must stay unchanged"
        );
        assert!(result.is_err(), "a foreign wallet parent must be refused");
    }

    #[tokio::test]
    async fn wallet_upgraded_home_with_group_writable_parent_still_starts() {
        let (_temp, data_dir, _) = wallet_fixture();
        let parent = data_dir.join("ElastOS/SystemServices");
        // Another service creates the shared level with `create_dir_all` under umask 002
        // (the signed test Home may already have created it).
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
        let wallet_root = parent.join("Wallet");
        prepare_wallet_storage_parent(&wallet_root).unwrap();
        let mode = fs::symlink_metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o755,
            "group and other write bits are removed and owner rwx is kept"
        );

        #[cfg(target_os = "linux")]
        {
            let registry = provider::ProviderRegistry::new();
            let bridge = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
                .await
                .unwrap()
                .unwrap();
            assert!(registry
                .registration_for_uri("elastos://wallet/status")
                .await
                .is_some());
            bridge.shutdown().await.unwrap();
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wallet_linux_admitted_row_answers_and_stays_confined() {
        let (_temp, data_dir, _) = wallet_fixture();
        let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
        let registry = provider::ProviderRegistry::new();
        let bridge = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .unwrap_or_else(|error| panic!("{error}; {}", wallet_probe_failure(&wallet_root)))
            .unwrap();
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_some());
        let created = registry
            .send_raw("wallet", &serde_json::json!({"op": "create_wallet"}))
            .await
            .unwrap();
        assert_eq!(created["data"]["created"], "a1");
        let listed = registry
            .send_raw("wallet", &serde_json::json!({"op": "list_wallets"}))
            .await
            .unwrap();
        assert_eq!(listed["data"]["accounts"], 1);
        let outside = registry
            .send_raw("wallet", &serde_json::json!({"op": "probe_outside_write"}))
            .await
            .unwrap();
        assert_eq!(outside["data"]["outside_write_refused"], true);

        let pid: libc::pid_t = fs::read_to_string(wallet_root.join("child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        bridge.shutdown().await.unwrap();
        assert_eq!(fs::read(wallet_root.join("shutdown")).unwrap(), b"yes");
        assert!(!Path::new(&format!("/proc/{pid}")).exists());

        let registry = provider::ProviderRegistry::new();
        let bridge = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        let listed = registry
            .send_raw("wallet", &serde_json::json!({"op": "list_wallets"}))
            .await
            .unwrap();
        assert_eq!(listed["data"]["accounts"], 1);
        bridge.shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wallet_unsuitable_parent_leaves_route_absent() {
        let (_temp, data_dir, _) = wallet_fixture();
        // The signed Home keeps its release under this level, so replacing it
        // with a file is refused when the provider is admitted (the release
        // envelope's parents are checked), before the signed-digest check and
        // before the storage parent is prepared; nothing is created.
        let parent = data_dir.join("ElastOS/SystemServices");
        fs::remove_dir_all(&parent).unwrap();
        fs::write(&parent, b"not a directory").unwrap();
        let registry = provider::ProviderRegistry::new();
        let error = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        let message = format!("{error:#}").to_lowercase();
        assert!(
            message.contains("installed release inputs require repair"),
            "{error:#}"
        );
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_none());
        assert!(!data_dir.join("ElastOS/SystemServices/Wallet").exists());
        assert!(!data_dir.join("marker").exists());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn wallet_registration_failure_reaps_the_confined_child() {
        let (_temp, data_dir, _) = wallet_fixture();
        let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
        let registry = provider::ProviderRegistry::new();
        registry
            .register_sub_provider(
                "wallet",
                Arc::new(DocumentsProvider::new(
                    data_dir.clone(),
                    std::sync::Weak::new(),
                )),
            )
            .await
            .unwrap();
        let error = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert!(
            error.to_string().contains("already registered"),
            "{error}; {}",
            wallet_probe_failure(&wallet_root)
        );
        assert_eq!(fs::read(wallet_root.join("shutdown")).unwrap(), b"yes");
        let pid: libc::pid_t = fs::read_to_string(wallet_root.join("child.pid"))
            .unwrap()
            .parse()
            .unwrap();
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[cfg(elastos_unsupported_os_check)]
    #[tokio::test]
    async fn wallet_os_refusal_leaves_marker_storage_and_route_absent() {
        let (_temp, data_dir, _) = wallet_fixture();
        let wallet_root = data_dir.join("ElastOS/SystemServices/Wallet");
        let registry = provider::ProviderRegistry::new();
        let error = start_wallet_provider(&data_dir, &registry, Duration::from_secs(1))
            .await
            .err()
            .unwrap();
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_none());
        assert!(!data_dir.join("marker").exists());
        assert!(!wallet_root.exists());
        assert!(!wallet_root.join("child.pid").exists());
        #[cfg(elastos_unsupported_os_check)]
        assert!(
            error
                .to_string()
                .contains("this operating system has no confinement"),
            "{error}"
        );
    }

    fn media_provider_status() -> serde_json::Value {
        serde_json::json!({
            "status": "ok",
            "data": {
                "provider": MEDIA_PROVIDER_ID,
                "protocol_version": MEDIA_PROVIDER_PROTOCOL_VERSION,
                "version": "0.7.2-alpha.5",
                "configured": true,
                "supported_operations": ["status", "prepare"],
            }
        })
    }

    fn setup_model_provider_operator_root(tempdir: &TempDir) -> PathBuf {
        let root = model_provider_root_dir(tempdir.path());
        fs::create_dir_all(&root).unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(
                tempdir.path().join("providers"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }

    fn write_model_provider_operator_config(tempdir: &TempDir, raw: &str) -> PathBuf {
        let root = setup_model_provider_operator_root(tempdir);
        let path = root.join(MODEL_PROVIDER_CONFIG_FILE_NAME);
        fs::write(&path, raw).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[cfg(unix)]
    fn write_protected_content_chain_config(tempdir: &TempDir) -> serde_json::Value {
        let protected_content_dir = tempdir.path().join("protected-content");
        fs::create_dir(&protected_content_dir).unwrap();
        fs::set_permissions(&protected_content_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let network = serde_json::json!({
            "id": "esc-mainnet",
            "display_name": "Protected ESC",
            "kind": "evm_json_rpc",
            "chain_id": 20,
            "native_symbol": "ELA",
            "provider": "operator",
            "mainnet": true,
            "explorer_url": null,
            "rpc_url": "https://private-primary.example.invalid",
            "rights_methods": [{
                "id": "has_access_by_content_id",
                "contract": "0x0000000000000000000000000000000000000001",
                "abi": "has_access_by_content_id_address_bytes16",
                "selector": "0x12345678",
                "protected_content_policies": [{
                    "action": "view",
                    "evidence_rpc_urls": [
                        "https://private-rights-a.example.invalid",
                        "https://private-rights-b.example.invalid"
                    ]
                }]
            }],
            "protected_content_creator_mint": {
                "ledger": "0x0000000000000000000000000000000000000022",
                "pay_token": "0x0000000000000000000000000000000000000033",
                "asset_created_emitter": "0x0000000000000000000000000000000000000044",
                "abi": "elacity_mint_v1"
            },
            "protected_content_market": {
                "authority_gateway_contract": "0x00000000000000000000000000000000000000aa",
                "evidence_rpc_urls": [
                    "https://private-market-a.example.invalid",
                    "https://private-market-b.example.invalid"
                ]
            }
        });
        let path = protected_content_dir.join("chain-provider.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema": elastos_server::protected_content_runtime::PROTECTED_CONTENT_CHAIN_PROVIDER_CONFIG_SCHEMA_V1,
                "protected_content_network": network
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        network
    }

    #[cfg(unix)]
    fn write_media_provider_operator_config(
        tempdir: &TempDir,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) -> PathBuf {
        let protected_content_root = tempdir.path().join("protected-content");
        let provider_root = media_provider_root_dir(tempdir.path());
        let tools_root = provider_root.join("tools");
        let staging_root = provider_root.join("staging");
        fs::create_dir_all(&tools_root).unwrap();
        fs::create_dir(&staging_root).unwrap();
        for path in [
            &protected_content_root,
            &provider_root,
            &tools_root,
            &staging_root,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ffmpeg_path = tools_root.join("ffmpeg");
        let ffprobe_path = tools_root.join("ffprobe");
        fs::write(&ffmpeg_path, b"ffmpeg-test").unwrap();
        fs::write(&ffprobe_path, b"ffprobe-test").unwrap();
        fs::set_permissions(&ffmpeg_path, fs::Permissions::from_mode(0o500)).unwrap();
        fs::set_permissions(&ffprobe_path, fs::Permissions::from_mode(0o500)).unwrap();
        let ffmpeg_path = fs::canonicalize(ffmpeg_path).unwrap();
        let ffprobe_path = fs::canonicalize(ffprobe_path).unwrap();
        let staging_root = fs::canonicalize(staging_root).unwrap();
        let mut value = serde_json::json!({
            "schema": "elastos.protected-content.media-provider-config/v1",
            "ffmpeg_path": ffmpeg_path,
            "ffprobe_path": ffprobe_path,
            "staging_root": staging_root,
            "output_profile": "browser_fmp4_h264_v1",
            "timeout_ms": 3_600_000u64,
            "max_stdio_bytes": 1usize << 20,
            "max_input_bytes": 1u64 << 30,
            "max_output_part_bytes": 64u64 << 20,
            "max_duration_secs": 1_800u64,
            "max_source_width": 3840,
            "max_source_height": 2160,
            "max_source_fps": 60,
            "max_segment_count": 512,
            "max_total_output_bytes": 2u64 << 30,
        });
        mutate(&mut value);
        let config_path = media_provider_config_path(tempdir.path());
        fs::write(&config_path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        config_path
    }

    #[cfg(unix)]
    fn read_pid(path: &Path) -> libc::pid_t {
        fs::read_to_string(path).unwrap().trim().parse().unwrap()
    }

    #[cfg(unix)]
    fn assert_pid_absent(pid: libc::pid_t) {
        let result = unsafe { libc::kill(pid, 0) };
        let err = std::io::Error::last_os_error();
        assert_eq!(result, -1, "pid {pid} should be absent");
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ESRCH),
            "pid {pid} should be reaped"
        );
    }

    #[cfg(unix)]
    fn create_test_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    #[cfg(unix)]
    fn write_initialized_media_provider_script(
        root: &Path,
        name: &str,
        status_response: &serde_json::Value,
    ) -> (PathBuf, PathBuf, PathBuf) {
        let binary = root.join(format!("{name}.sh"));
        let pid_file = root.join(format!("{name}.pid"));
        let request_log = root.join(format!("{name}.requests"));
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *'\"op\":\"status\"'*) printf '%s\\n' '{}' ;;\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *) exit 1 ;;\n  esac\ndone\n",
            pid_file.display(),
            request_log.display(),
            status_response,
        );
        crate::test_support::write_from_child(&binary, script, 0o700);
        (binary, pid_file, request_log)
    }

    #[cfg(unix)]
    fn write_blocking_media_status_script(
        root: &Path,
    ) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let binary = root.join("media-provider-timeout.sh");
        let pid_file = root.join("media-provider-timeout.pid");
        let request_log = root.join("media-provider-timeout.requests");
        let status_signal = root.join("media-provider-status.signal");
        let status_release = root.join("media-provider-status.release");
        create_test_fifo(&status_signal);
        create_test_fifo(&status_release);
        let script = format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$$\" > '{}'\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  case \"$line\" in\n    *'\"op\":\"init\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}' ;;\n    *'\"op\":\"status\"'*) printf x > '{}'; cat '{}' >/dev/null; printf '%s\\n' '{}' ;;\n    *'\"op\":\"shutdown\"'*) printf '%s\\n' '{{\"status\":\"ok\"}}'; exit 0 ;;\n    *) exit 1 ;;\n  esac\ndone\n",
            pid_file.display(),
            request_log.display(),
            status_signal.display(),
            status_release.display(),
            media_provider_status(),
        );
        crate::test_support::write_from_child(&binary, script, 0o700);
        (binary, pid_file, request_log, status_signal, status_release)
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn browser_helper_pipe_closes_with_runtime_provider_shutdown() {
        let temp = tempfile::tempdir().unwrap();
        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../scripts/browser-helper-parent-lifetime.test.py");
        let binary = temp.path().join("browser-provider.sh");
        crate::test_support::write_from_child(
            &binary,
            format!(
                "#!/bin/sh\nexec python3 '{}' --provider '{}'\n",
                script.display(),
                temp.path().display()
            ),
            0o700,
        );
        let bridge = provider::ProviderBridge::spawn_with_owned_helpers(
            &crate::test_support::fixture_executable(&binary),
            Default::default(),
        )
        .await
        .unwrap();
        let ready: serde_json::Value =
            serde_json::from_slice(&fs::read(temp.path().join("ready.json")).unwrap()).unwrap();
        let pid = ready["helper"].as_u64().unwrap() as libc::pid_t;
        bridge.shutdown().await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while unsafe { libc::kill(pid, 0) } == 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let gone = unsafe { libc::kill(pid, 0) } != 0;
        if !gone {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        assert!(gone, "Browser helper outlived Runtime provider shutdown");
        assert!(temp.path().join("clean-stop").exists());
    }

    #[tokio::test]
    async fn browser_engine_startup_registers_only_exact_identity_and_version() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) = test_provider_bridge(
            provider_status(BROWSER_ENGINE_PROVIDER_ID, BROWSER_ENGINE_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        start_browser_engine_provider(&registry, bridge, Duration::from_secs(1))
            .await
            .unwrap();

        let registration = registry
            .registration_for_uri("elastos://browser-engine/status")
            .await
            .unwrap();
        assert_eq!(registration.route, "browser-engine");
        assert_eq!(registration.provider, "capsule-provider");
        provider.abort();
    }

    #[tokio::test]
    async fn browser_engine_startup_reaps_old_or_mixed_version_before_launch() {
        for status in [
            provider_status(BROWSER_ENGINE_PROVIDER_ID, "1.0"),
            provider_status(BROWSER_ENGINE_PROVIDER_ID, "2.0"),
            provider_status(BROWSER_ENGINE_PROVIDER_ID, "2.2"),
            provider_status("other-provider", BROWSER_ENGINE_PROTOCOL_VERSION),
        ] {
            let registry = provider::ProviderRegistry::new();
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            let error = start_browser_engine_provider(&registry, bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(error.to_string().contains("unsupported"));
            assert!(registry
                .registration_for_uri("elastos://browser-engine/launch")
                .await
                .is_none());
            let requests = provider.await.unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0]["op"], "status");
            assert_eq!(requests[1]["op"], "shutdown");
            assert!(!requests.iter().any(|request| request["op"] == "launch"));
        }
    }

    #[tokio::test]
    async fn browser_engine_startup_reaps_failed_or_malformed_status() {
        for status in [
            serde_json::json!({"status": "error"}),
            serde_json::json!({"status": "ok", "data": []}),
            serde_json::json!({
                "status": "ok",
                "data": {
                    "provider": BROWSER_ENGINE_PROVIDER_ID,
                }
            }),
        ] {
            let registry = provider::ProviderRegistry::new();
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            start_browser_engine_provider(&registry, bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(registry
                .registration_for_uri("elastos://browser-engine/status")
                .await
                .is_none());
            let requests = provider.await.unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0]["op"], "status");
            assert_eq!(requests[1]["op"], "shutdown");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn browser_engine_status_probe_completes_within_its_bound() {
        let (bridge, provider) = test_provider_bridge(
            provider_status(BROWSER_ENGINE_PROVIDER_ID, BROWSER_ENGINE_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let started = tokio::time::Instant::now();
        let error = request_browser_engine_provider_status(&bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert_eq!(started.elapsed(), Duration::from_millis(5));
        provider.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn browser_engine_startup_reaps_provider_that_does_not_answer_in_time() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) = test_provider_bridge(
            provider_status(BROWSER_ENGINE_PROVIDER_ID, BROWSER_ENGINE_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let error = start_browser_engine_provider(&registry, bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(registry
            .registration_for_uri("elastos://browser-engine/status")
            .await
            .is_none());
        let requests = provider.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
    }

    #[tokio::test]
    async fn browser_engine_startup_reaps_provider_when_registration_fails() {
        let registry = provider::ProviderRegistry::new();
        let (first_bridge, first_provider) = test_provider_bridge(
            provider_status(BROWSER_ENGINE_PROVIDER_ID, BROWSER_ENGINE_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        start_browser_engine_provider(&registry, first_bridge, Duration::from_secs(1))
            .await
            .unwrap();

        let (second_bridge, second_provider) = test_provider_bridge(
            provider_status(BROWSER_ENGINE_PROVIDER_ID, BROWSER_ENGINE_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        let error = start_browser_engine_provider(&registry, second_bridge, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed to register"));

        let requests = second_provider.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
        first_provider.abort();
    }

    #[tokio::test]
    async fn wallet_provider_v2_status_rejects_identity_or_version_mismatch() {
        for status in [
            provider_status("wallet-provider", "2.0"),
            provider_status("wallet-provider", "2.1"),
            provider_status("wallet-provider", "2.2"),
            provider_status("wallet-provider", "1.0"),
            provider_status("other-provider", WALLET_PROTOCOL_VERSION),
        ] {
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            let error = check_wallet_provider_v2_status(&bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(error.to_string().contains("unsupported"));
            provider.abort();
        }
    }

    #[tokio::test]
    async fn wallet_provider_v2_status_rejects_failed_or_malformed_data() {
        for status in [
            serde_json::json!({"status": "error"}),
            serde_json::json!({"status": "ok", "data": []}),
        ] {
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            check_wallet_provider_v2_status(&bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            provider.abort();
        }
    }

    #[tokio::test]
    async fn wallet_provider_v2_status_failure_reaps_the_provider() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) =
            test_provider_bridge(provider_status("wallet-provider", "1.0"), Duration::ZERO);
        let wallet_provider: Arc<dyn provider::Provider> = Arc::new(
            provider::CapsuleProvider::with_scheme(Arc::clone(&bridge), "wallet"),
        );

        let error = check_and_register_wallet_provider_v2(
            &registry,
            bridge,
            wallet_provider,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("unsupported"), "{error}");
        assert!(registry
            .registration_for_uri("elastos://wallet/status")
            .await
            .is_none());
        let requests = provider.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
    }

    #[tokio::test(start_paused = true)]
    async fn wallet_provider_v2_status_probe_completes_within_its_bound() {
        let (bridge, provider) = test_provider_bridge(
            provider_status("wallet-provider", WALLET_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let started = tokio::time::Instant::now();
        let error = request_wallet_provider_v2_status(&bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert_eq!(started.elapsed(), Duration::from_millis(5));
        provider.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn wallet_provider_v2_status_probe_times_out_without_an_answer() {
        let (bridge, provider) = test_provider_bridge(
            provider_status("wallet-provider", WALLET_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let error = check_wallet_provider_v2_status(&bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        provider.abort();
    }

    #[tokio::test]
    async fn model_provider_startup_registers_only_exact_identity_and_version() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) = test_provider_bridge(
            provider_status(MODEL_PROVIDER_ID, MODEL_PROVIDER_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        start_model_provider(&registry, bridge, Duration::from_secs(1))
            .await
            .unwrap();

        let registration = registry
            .registration_for_uri("elastos://model/offers")
            .await
            .unwrap();
        assert_eq!(registration.route, "model");
        assert_eq!(registration.provider, "capsule-provider");
        provider.abort();
    }

    #[tokio::test]
    async fn model_provider_startup_reaps_identity_or_version_mismatch() {
        for status in [
            provider_status(MODEL_PROVIDER_ID, "1.0"),
            provider_status(MODEL_PROVIDER_ID, "2.0"),
            provider_status("other-provider", MODEL_PROVIDER_PROTOCOL_VERSION),
        ] {
            let registry = provider::ProviderRegistry::new();
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            let error = start_model_provider(&registry, bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(error.to_string().contains("unsupported"));
            assert!(registry
                .registration_for_uri("elastos://model/offers")
                .await
                .is_none());
            let requests = provider.await.unwrap();
            assert_eq!(requests[0]["op"], "status");
            assert_eq!(requests[1]["op"], "shutdown");
        }
    }

    #[tokio::test]
    async fn model_provider_startup_reaps_failed_or_malformed_status() {
        for status in [
            serde_json::json!({"status": "error"}),
            serde_json::json!({"status": "ok", "data": []}),
            serde_json::json!({
                "status": "ok",
                "data": {
                    "provider": MODEL_PROVIDER_ID,
                }
            }),
        ] {
            let registry = provider::ProviderRegistry::new();
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);
            start_model_provider(&registry, bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(registry
                .registration_for_uri("elastos://model/offers")
                .await
                .is_none());
            let requests = provider.await.unwrap();
            assert_eq!(requests[0]["op"], "status");
            assert_eq!(requests[1]["op"], "shutdown");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn model_provider_status_probe_completes_within_its_bound() {
        let (bridge, provider) = test_provider_bridge(
            provider_status(MODEL_PROVIDER_ID, MODEL_PROVIDER_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let started = tokio::time::Instant::now();
        let error = request_model_provider_status(&bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert_eq!(started.elapsed(), Duration::from_millis(5));
        provider.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn model_provider_startup_reaps_provider_that_does_not_answer_in_time() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) = test_provider_bridge(
            provider_status(MODEL_PROVIDER_ID, MODEL_PROVIDER_PROTOCOL_VERSION),
            Duration::from_millis(20),
        );
        let error = start_model_provider(&registry, bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert!(registry
            .registration_for_uri("elastos://model/offers")
            .await
            .is_none());
        let requests = provider.await.unwrap();
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
    }

    #[tokio::test]
    async fn model_provider_startup_reaps_provider_when_registration_fails() {
        let registry = provider::ProviderRegistry::new();
        let (first_bridge, first_provider) = test_provider_bridge(
            provider_status(MODEL_PROVIDER_ID, MODEL_PROVIDER_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        start_model_provider(&registry, first_bridge, Duration::from_secs(1))
            .await
            .unwrap();

        let (second_bridge, second_provider) = test_provider_bridge(
            provider_status(MODEL_PROVIDER_ID, MODEL_PROVIDER_PROTOCOL_VERSION),
            Duration::ZERO,
        );
        let error = start_model_provider(&registry, second_bridge, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("failed to register"));

        let requests = second_provider.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
        first_provider.abort();
    }

    #[tokio::test]
    async fn media_provider_startup_accepts_another_release_and_registers_only_the_runtime_media_route(
    ) {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) = test_provider_bridge(media_provider_status(), Duration::ZERO);

        start_media_provider(&registry, bridge, Duration::from_secs(1))
            .await
            .unwrap();

        assert!(registry
            .registration_for_uri("elastos://media/status")
            .await
            .is_none());
        assert!(
            registry
                .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                .await
        );
        provider.abort();
    }

    #[tokio::test]
    async fn media_provider_startup_reaps_mismatched_or_unconfigured_processes() {
        let mut cases = Vec::new();
        let mut wrong_identity = media_provider_status();
        wrong_identity["data"]["provider"] = serde_json::json!("other-provider");
        cases.push(wrong_identity);
        let mut wrong_protocol = media_provider_status();
        wrong_protocol["data"]["protocol_version"] = serde_json::json!("old");
        cases.push(wrong_protocol);
        let mut wrong_version = media_provider_status();
        wrong_version["data"]["version"] = serde_json::json!("old");
        cases.push(wrong_version);
        let mut unconfigured = media_provider_status();
        unconfigured["data"]["configured"] = serde_json::json!(false);
        cases.push(unconfigured);
        let mut wrong_operations = media_provider_status();
        wrong_operations["data"]["supported_operations"] =
            serde_json::json!(["status", "prepare", "publish"]);
        cases.push(wrong_operations);
        let mut reordered_operations = media_provider_status();
        reordered_operations["data"]["supported_operations"] =
            serde_json::json!(["prepare", "status"]);
        cases.push(reordered_operations);
        let mut missing_operations = media_provider_status();
        missing_operations["data"]["supported_operations"] = serde_json::json!(["status"]);
        cases.push(missing_operations);
        let mut extra_data = media_provider_status();
        extra_data["data"]["route"] = serde_json::json!("private");
        cases.push(extra_data);
        let mut extra_top = media_provider_status();
        extra_top["route"] = serde_json::json!("private");
        cases.push(extra_top);
        cases.push(serde_json::json!({"status": "ok"}));
        cases.push(serde_json::json!({"status": "error", "data": {}}));

        for status in cases {
            let registry = provider::ProviderRegistry::new();
            let (bridge, provider) = test_provider_bridge(status, Duration::ZERO);

            start_media_provider(&registry, bridge, Duration::from_secs(1))
                .await
                .unwrap_err();

            assert!(registry
                .registration_for_uri("elastos://media/status")
                .await
                .is_none());
            assert!(
                !registry
                    .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                    .await
            );
            let requests = provider.await.unwrap();
            assert_eq!(requests[0]["op"], "status");
            assert_eq!(requests[1]["op"], "shutdown");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn media_provider_status_and_failed_startup_are_bounded_and_settled() {
        let registry = provider::ProviderRegistry::new();
        let (bridge, provider) =
            test_provider_bridge(media_provider_status(), Duration::from_millis(20));
        let started = tokio::time::Instant::now();

        let error = start_media_provider(&registry, bridge, Duration::from_millis(5))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("timed out"));
        assert_eq!(started.elapsed(), Duration::from_millis(20));
        assert!(registry
            .registration_for_uri("elastos://media/status")
            .await
            .is_none());
        assert!(
            !registry
                .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                .await
        );
        let requests = provider.await.unwrap();
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
    }

    #[tokio::test]
    async fn media_provider_duplicate_registration_reaps_the_rejected_process() {
        let registry = provider::ProviderRegistry::new();
        let (first_bridge, first_provider) =
            test_provider_bridge(media_provider_status(), Duration::ZERO);
        start_media_provider(&registry, first_bridge, Duration::from_secs(1))
            .await
            .unwrap();
        let (second_bridge, second_provider) =
            test_provider_bridge(media_provider_status(), Duration::ZERO);

        let error = start_media_provider(&registry, second_bridge, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed to register"));
        assert!(
            registry
                .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                .await
        );
        let requests = second_provider.await.unwrap();
        assert_eq!(requests[0]["op"], "status");
        assert_eq!(requests[1]["op"], "shutdown");
        first_provider.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn media_provider_startup_reaps_real_child_after_status_rejection() {
        let tempdir = TempDir::new().unwrap();
        let registry = provider::ProviderRegistry::new();
        let mut status = media_provider_status();
        status["data"]["provider"] = serde_json::json!("wrong-provider");
        let (script_path, pid_path, request_log) = write_initialized_media_provider_script(
            tempdir.path(),
            "media-provider-rejected",
            &status,
        );
        let bridge = Arc::new(
            provider::ProviderBridge::spawn(
                &crate::test_support::fixture_executable(&script_path),
                Default::default(),
            )
            .await
            .unwrap(),
        );

        let error = start_media_provider(&registry, bridge, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("unsupported provider identity"));
        assert!(
            !registry
                .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                .await
        );
        let pid = read_pid(&pid_path);
        assert_pid_absent(pid);
        let requests = fs::read_to_string(request_log).unwrap();
        assert!(requests.contains(r#""op":"status""#));
        assert!(requests.contains(r#""op":"shutdown""#));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn media_provider_duplicate_registration_reaps_real_rejected_child() {
        let tempdir = TempDir::new().unwrap();
        let registry = provider::ProviderRegistry::new();
        let first_root = tempdir.path().join("first");
        let second_root = tempdir.path().join("second");
        fs::create_dir_all(&first_root).unwrap();
        fs::create_dir_all(&second_root).unwrap();
        let (first_binary, first_pid_path, _) = write_initialized_media_provider_script(
            &first_root,
            "media-provider",
            &media_provider_status(),
        );
        let (second_binary, second_pid_path, second_log) = write_initialized_media_provider_script(
            &second_root,
            "media-provider",
            &media_provider_status(),
        );
        let first_bridge = Arc::new(
            provider::ProviderBridge::spawn(
                &crate::test_support::fixture_executable(&first_binary),
                Default::default(),
            )
            .await
            .unwrap(),
        );
        start_media_provider(&registry, first_bridge, Duration::from_secs(1))
            .await
            .unwrap();
        let first_pid = read_pid(&first_pid_path);

        let second_bridge = Arc::new(
            provider::ProviderBridge::spawn(
                &crate::test_support::fixture_executable(&second_binary),
                Default::default(),
            )
            .await
            .unwrap(),
        );
        let error = start_media_provider(&registry, second_bridge, Duration::from_secs(1))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("failed to register"));
        assert_pid_absent(read_pid(&second_pid_path));
        let requests = fs::read_to_string(second_log).unwrap();
        assert!(requests.contains(r#""op":"status""#));
        assert!(requests.contains(r#""op":"shutdown""#));
        registry
            .unregister_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
            .await
            .unwrap();
        assert_pid_absent(first_pid);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn media_provider_status_timeout_sends_shutdown_and_reaps_real_child() {
        let tempdir = TempDir::new().unwrap();
        let registry = Arc::new(provider::ProviderRegistry::new());
        let (binary, pid_path, request_log, status_signal, status_release) =
            write_blocking_media_status_script(tempdir.path());
        let bridge = Arc::new(
            provider::ProviderBridge::spawn(
                &crate::test_support::fixture_executable(&binary),
                Default::default(),
            )
            .await
            .unwrap(),
        );
        let task_registry = registry.clone();
        let registration = tokio::spawn(async move {
            start_media_provider(&task_registry, bridge, Duration::from_secs(5)).await
        });

        let mut signal = tokio::fs::OpenOptions::new()
            .read(true)
            .open(&status_signal)
            .await
            .unwrap();
        let mut marker = [0u8; 1];
        signal.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [b'x']);
        tokio::time::pause();
        let release_status = tokio::spawn(async move {
            let release = tokio::time::timeout(
                Duration::from_secs(5) + Duration::from_millis(1),
                std::future::pending::<()>(),
            )
            .await;
            assert!(release.is_err());
            let mut release = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&status_release)
                .await
                .unwrap();
            release.write_all(b"x").await.unwrap();
        });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5) + Duration::from_millis(1)).await;
        tokio::time::resume();
        release_status.await.unwrap();

        let error = registration.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("status request timed out"));
        assert_pid_absent(read_pid(&pid_path));
        let requests = fs::read_to_string(request_log).unwrap();
        assert!(requests.contains(r#""op":"status""#));
        assert!(requests.contains(r#""op":"shutdown""#));
        assert!(
            !registry
                .has_ready_runtime_provider_target(MEDIA_PROVIDER_ROUTE)
                .await
        );
    }

    #[cfg(unix)]
    #[test]
    fn media_provider_config_is_private_bounded_and_path_fixed() {
        let absent = TempDir::new().unwrap();
        assert!(media_provider_bridge_config(absent.path())
            .unwrap()
            .is_none());

        let valid = TempDir::new().unwrap();
        let path = write_media_provider_operator_config(&valid, |_| {});
        let original = fs::read(&path).unwrap();
        let config = media_provider_bridge_config(valid.path()).unwrap().unwrap();
        assert_eq!(config.extra["provider_id"], MEDIA_PROVIDER_ID);
        let expected_staging =
            fs::canonicalize(media_provider_root_dir(valid.path()).join("staging")).unwrap();
        assert_eq!(
            config.extra["staging_root"].as_str(),
            expected_staging.to_str()
        );
        assert_eq!(fs::read(&path).unwrap(), original);

        let invalid_cases: [fn(&mut serde_json::Value); 3] = [
            |value: &mut serde_json::Value| value["timeout_ms"] = serde_json::json!(3_600_001u64),
            |value: &mut serde_json::Value| {
                value["max_input_bytes"] = serde_json::json!((1u64 << 30) + 1)
            },
            |value: &mut serde_json::Value| {
                value["staging_root"] = serde_json::json!("/private/tmp/escaped")
            },
        ];
        for mutate in invalid_cases {
            let tempdir = TempDir::new().unwrap();
            write_media_provider_operator_config(&tempdir, mutate);
            assert!(media_provider_bridge_config(tempdir.path()).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn media_provider_config_rejects_links_and_redacts_private_values() {
        let tempdir = TempDir::new().unwrap();
        let config_path = write_media_provider_operator_config(&tempdir, |value| {
            value["secret"] = serde_json::json!("super-secret-private-path")
        });
        let error = media_provider_bridge_config(tempdir.path()).unwrap_err();
        assert!(!error.to_string().contains("super-secret-private-path"));
        fs::remove_file(&config_path).unwrap();

        let target = tempdir.path().join("linked-config");
        fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &config_path).unwrap();
        assert!(media_provider_bridge_config(tempdir.path()).is_err());
    }

    #[test]
    fn model_provider_bridge_config_uses_empty_offers_when_config_is_absent() {
        let tempdir = TempDir::new().unwrap();

        let config = model_provider_bridge_config(tempdir.path()).unwrap();

        let canonical_root = tempdir.path().canonicalize().unwrap();
        assert_eq!(config.base_path, canonical_root.to_string_lossy());
        assert_eq!(config.extra["provider_id"], MODEL_PROVIDER_ID);
        assert_eq!(
            config.extra["journal_dir"],
            model_provider_journal_dir(&canonical_root)
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(config.extra["offers"], serde_json::json!([]));
        assert!(!model_provider_config_path(tempdir.path()).exists());
    }

    #[tokio::test]
    async fn model_provider_startup_config_keeps_operator_offers_without_admission() {
        let tempdir = TempDir::new().unwrap();
        let raw = r#"{"offers":[{"id":"operator-owned","enabled":false}]}"#;
        let path = write_model_provider_operator_config(&tempdir, raw);
        let expected = model_provider_bridge_config(tempdir.path()).unwrap();
        let registry = provider::ProviderRegistry::new();
        let (actual, worker) = model_provider_startup_config(tempdir.path(), &registry)
            .await
            .unwrap();
        assert!(worker.is_none());
        assert_eq!(
            serde_json::to_value(&actual).unwrap(),
            serde_json::to_value(&expected).unwrap()
        );
        assert_eq!(fs::read_to_string(path).unwrap(), raw);
        assert!(!tempdir.path().join("model-preparation").exists());
        assert!(!model_provider_journal_dir(tempdir.path()).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_provider_startup_config_resolves_root_alias_to_same_init_identity() {
        let tempdir = TempDir::new().unwrap();
        let raw = r#"{"offers":[{"id":"operator-owned","enabled":false}]}"#;
        let operator_path = write_model_provider_operator_config(&tempdir, raw);
        let links = TempDir::new().unwrap();
        let alias = links.path().join("runtime-root");
        std::os::unix::fs::symlink(tempdir.path(), &alias).unwrap();
        let registry = provider::ProviderRegistry::new();
        let initial = model_provider_bridge_config(&alias).unwrap();
        let (refreshed, worker) = model_provider_startup_config(&alias, &registry)
            .await
            .unwrap();
        assert!(worker.is_none());
        let canonical =
            model_provider_bridge_config(&tempdir.path().canonicalize().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(initial).unwrap(),
            serde_json::to_value(&canonical).unwrap()
        );
        assert_eq!(
            serde_json::to_value(refreshed).unwrap(),
            serde_json::to_value(canonical).unwrap()
        );
        assert_eq!(fs::read_to_string(operator_path).unwrap(), raw);
        assert!(!model_provider_journal_dir(tempdir.path()).exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn model_provider_startup_config_consumes_inventory_validation() {
        let tempdir = TempDir::new().unwrap();
        assert!(model_provider_bridge_config(tempdir.path()).is_ok());
        let inventory = tempdir.path().join("model-preparation");
        fs::create_dir(&inventory).unwrap();
        fs::set_permissions(&inventory, fs::Permissions::from_mode(0o700)).unwrap();
        // An existing incomplete inventory is not the absent-inventory case.
        let registry = provider::ProviderRegistry::new();
        assert!(model_provider_startup_config(tempdir.path(), &registry)
            .await
            .is_err());
        assert!(!inventory.join("lock").exists());
        assert!(!model_provider_journal_dir(tempdir.path()).exists());
    }

    fn plant_device_key(data_dir: &std::path::Path, device_key: &[u8; 32]) {
        let identity = data_dir.join("identity");
        fs::create_dir_all(&identity).unwrap();
        fs::write(identity.join("device.key"), device_key).unwrap();
    }

    fn assert_init_omits_device_key(config: provider::BridgeProviderConfig, device_key: &[u8; 32]) {
        let device_key_hex = hex::encode(device_key);
        assert_eq!(device_key_hex.len(), 64);
        assert!(config.encryption_key.is_empty());
        let init =
            serde_json::to_value(provider::bridge::ProviderRequest::Init { config }).unwrap();
        assert_eq!(init["op"], "init");
        assert_eq!(init["config"]["encryption_key"], "");
        let serialized = serde_json::to_string(&init).unwrap();
        assert!(
            !serialized.contains(&device_key_hex),
            "init JSON contains the device private key: {serialized}"
        );
    }

    #[test]
    fn wallet_provider_config_omits_device_key() {
        let device_key = [0x5a; 32];
        let temp = TempDir::new().unwrap();
        plant_device_key(temp.path(), &device_key);
        assert_eq!(
            fs::read(temp.path().join("identity/device.key")).unwrap(),
            device_key
        );
        let source = include_str!("server_infra.rs");
        let body = source
            .split_once("\nasync fn start_wallet_provider(")
            .unwrap()
            .1
            .split_once("\nasync fn request_model_provider_status(")
            .unwrap()
            .0;
        assert!(body.contains("wallet_provider_bridge_config("));
        assert!(!body.contains("device_key"));
        assert!(!body.contains("encryption_key"));
        assert_init_omits_device_key(wallet_provider_bridge_config(temp.path()), &device_key);
    }

    #[test]
    fn object_provider_config_omits_device_key() {
        let device_key = [0x5a; 32];
        let temp = TempDir::new().unwrap();
        plant_device_key(temp.path(), &device_key);
        assert_eq!(
            fs::read(temp.path().join("identity/device.key")).unwrap(),
            device_key
        );
        let source = include_str!("server_infra.rs");
        let region = source
            .split_once("resolve_verified_native_provider_binary(\"object-provider\")")
            .unwrap()
            .1
            .split_once("resolve_verified_native_provider_binary(\"webspace-provider\")")
            .unwrap()
            .0;
        assert!(region.contains("object_provider_bridge_config("));
        assert!(!region.contains("device_key_hex"));
        assert!(!region.contains("encryption_key:"));
        assert_init_omits_device_key(object_provider_bridge_config(temp.path()), &device_key);
    }

    fn assert_current_marker(root: &std::path::Path, device_key: &[u8; 32]) {
        let file_key = expected_localhost_file_key(device_key);
        let bytes = fs::read(root.join("identity/localhost-file-key-v1")).unwrap();
        assert_eq!(
            bytes,
            crate::localhost_file_migration::localhost_marker_record(&file_key)
        );
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(&hex::encode(file_key)), "{text}");
    }

    fn expected_localhost_file_key(device_key: &[u8; 32]) -> [u8; 32] {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, device_key);
        let mut okm = [0u8; 32];
        hk.expand(b"elastos-localhost-file-v1", &mut okm).unwrap();
        okm
    }

    fn assert_no_localhost_rewrite_temps(dir: &std::path::Path) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            let text = name.to_string_lossy();
            assert!(
                !text.contains("elastos-localhost-file-key-v1.tmp"),
                "rewrite temp left behind: {text}"
            );
            if entry.file_type().unwrap().is_dir() {
                assert_no_localhost_rewrite_temps(&entry.path());
            }
        }
    }

    #[test]
    fn an_all_zero_device_key_is_refused_by_name() {
        let err = localhost_file_key(&[0u8; 32]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("identity/device.key"), "{text}");
        assert!(text.contains("all zero"), "{text}");
        assert!(localhost_file_key(&[1u8; 32]).is_ok());

        let planted_key = [0x91u8; 32];
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("Users/zero.bin");
        let planted = plant_device_envelope(&path, &planted_key, b"kept");
        let err = localhost_provider_bridge_config(temp.path(), &[0u8; 32]).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("identity/device.key"), "{text}");
        assert!(text.contains("all zero"), "{text}");
        assert_eq!(fs::read(&path).unwrap(), planted);
        assert!(!temp.path().join("identity/localhost-file-key-v1").exists());
    }

    #[test]
    fn localhost_provider_config_omits_device_key() {
        let device_key = [0x5a; 32];
        let other_key = [0x5b; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let other_file_key = expected_localhost_file_key(&other_key);
        assert_ne!(file_key, device_key);
        assert_ne!(other_file_key, other_key);
        assert_ne!(file_key, other_file_key);
        assert_eq!(localhost_file_key(&device_key).unwrap(), file_key);
        assert_eq!(localhost_file_key(&other_key).unwrap(), other_file_key);
        let temp = TempDir::new().unwrap();
        plant_device_key(temp.path(), &device_key);
        let device_key_bytes = fs::read(temp.path().join("identity/device.key")).unwrap();
        assert_eq!(device_key_bytes, device_key);

        let config = localhost_provider_bridge_config(temp.path(), &device_key).unwrap();

        assert_eq!(
            fs::read(temp.path().join("identity/device.key")).unwrap(),
            device_key
        );
        assert_eq!(config.encryption_key, hex::encode(file_key));
        assert_ne!(config.encryption_key, hex::encode(device_key));
        let init =
            serde_json::to_value(provider::bridge::ProviderRequest::Init { config }).unwrap();
        assert_eq!(init["op"], "init");
        assert_eq!(init["config"]["encryption_key"], hex::encode(file_key));
        let serialized = serde_json::to_string(&init).unwrap();
        assert!(
            !serialized.contains(&hex::encode(device_key)),
            "init JSON contains the device private key: {serialized}"
        );
        assert_eq!(
            hex::encode(file_key),
            "1c07c28ca30027630df2bd6a9a472abd747127757c2c6a793cdca2eefbd14e15"
        );
        let marker = fs::read(temp.path().join("identity/localhost-file-key-v1")).unwrap();
        let marker_text = String::from_utf8(marker).unwrap();
        assert!(marker_text.starts_with("elastos-localhost-file-v1 1 "));
        assert!(marker_text
            .contains("60b7efb43e2d46bc312c9d9e9eae6ad4164d6b0ea67a13d53e7e025bba8d707d"));
        assert!(!marker_text.contains(&hex::encode(file_key)));
        assert!(!marker_text.contains(&hex::encode(device_key)));
    }

    #[test]
    fn migrated_localhost_envelope_roundtrip() {
        let device_key = [0x11; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let plaintext = b"local-app secret";
        let original = localhost_provider::encrypt_bytes(&device_key, plaintext).unwrap();
        for dir in [
            "AppCapsules",
            "ElastOS/SystemServices",
            "Local",
            "Users/person",
            "UsersAI",
        ] {
            let folder = root.join(dir);
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join("note.bin"), &original).unwrap();
        }
        fs::write(root.join("Users/readme.txt"), b"plain").unwrap();
        fs::write(root.join("Users/meta.json"), br#"{"version":1}"#).unwrap();
        fs::create_dir_all(root.join("identity")).unwrap();
        fs::write(root.join("identity/credentials.json"), &original).unwrap();
        fs::create_dir_all(root.join("did")).unwrap();
        fs::write(root.join("did/nickname.enc"), &original).unwrap();
        fs::create_dir_all(root.join("Public")).unwrap();
        fs::write(root.join("Public/page.bin"), &original).unwrap();
        fs::create_dir_all(root.join("MyWebSite")).unwrap();
        fs::write(root.join("MyWebSite/index.bin"), &original).unwrap();

        let config = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(config.encryption_key, hex::encode(file_key));

        for dir in [
            "AppCapsules",
            "ElastOS/SystemServices",
            "Local",
            "Users/person",
            "UsersAI",
        ] {
            let migrated = fs::read(root.join(dir).join("note.bin")).unwrap();
            assert_ne!(migrated, original);
            assert_eq!(
                localhost_provider::decrypt_bytes(&file_key, &migrated).unwrap(),
                plaintext
            );
            assert!(localhost_provider::decrypt_bytes(&device_key, &migrated).is_err());
        }
        assert_eq!(fs::read(root.join("Users/readme.txt")).unwrap(), b"plain");
        assert_eq!(
            fs::read(root.join("Users/meta.json")).unwrap(),
            br#"{"version":1}"#
        );
        assert_eq!(
            fs::read(root.join("identity/credentials.json")).unwrap(),
            original
        );
        assert_eq!(fs::read(root.join("did/nickname.enc")).unwrap(), original);
        assert_eq!(fs::read(root.join("Public/page.bin")).unwrap(), original);
        assert_eq!(
            fs::read(root.join("MyWebSite/index.bin")).unwrap(),
            original
        );
        assert_current_marker(root, &device_key);
        assert_no_localhost_rewrite_temps(root);

        let sealed = fs::read(root.join("Users/person/note.bin")).unwrap();
        let again = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(again.encryption_key, hex::encode(file_key));
        assert_eq!(
            fs::read(root.join("Users/person/note.bin")).unwrap(),
            sealed
        );
        assert_eq!(
            fs::read(root.join("identity/credentials.json")).unwrap(),
            original
        );
        assert_current_marker(root, &device_key);

        let later_path = root.join("Local/later.bin");
        let later = localhost_provider::encrypt_bytes(&device_key, b"later").unwrap();
        fs::write(&later_path, &later).unwrap();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_ne!(fs::read(&later_path).unwrap(), later);
        assert_envelope_opens_with_exactly_one_key(&later_path, b"later", &device_key, &file_key);
    }

    #[test]
    fn corrupt_localhost_envelope_stops_start_and_names_the_file() {
        let device_key = [0x22; 32];
        let temp = TempDir::new().unwrap();
        let path = temp
            .path()
            .join("Users")
            .join("corrupt-localhost-envelope.bin");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let corrupt = localhost_provider::encrypt_bytes(&[0x99; 32], b"other-home").unwrap();
        fs::write(&path, &corrupt).unwrap();

        let err = localhost_provider_bridge_config(temp.path(), &device_key).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("Users/corrupt-localhost-envelope.bin"),
            "{message}"
        );
        assert!(
            !message.contains(temp.path().to_str().unwrap()),
            "{message}"
        );
        assert!(message.contains("not decryptable"), "{message}");
        assert!(message.contains("Remove it, then restart."), "{message}");
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        assert!(!temp.path().join("identity/localhost-file-key-v1").exists());
        let names: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["corrupt-localhost-envelope.bin".to_string()]);
    }

    #[test]
    fn localhost_link_stops_start_and_leaves_outside_bytes_unchanged() {
        let device_key = [0x33; 32];
        let original = localhost_provider::encrypt_bytes(&device_key, b"credential").unwrap();

        let linked = TempDir::new().unwrap();
        fs::create_dir_all(linked.path().join("identity")).unwrap();
        let creds = linked.path().join("identity/credentials.json");
        fs::write(&creds, &original).unwrap();
        fs::create_dir_all(linked.path().join("Users")).unwrap();
        let alias = linked.path().join("Users/alias.json");
        std::os::unix::fs::symlink(&creds, &alias).unwrap();
        let err = localhost_provider_bridge_config(linked.path(), &device_key).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Users/alias.json"), "{message}");
        assert!(message.contains(" is linked."), "{message}");
        assert_eq!(fs::read(&creds).unwrap(), original);
        assert!(fs::symlink_metadata(&alias)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!linked
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());

        let shared = TempDir::new().unwrap();
        fs::create_dir_all(shared.path().join("identity")).unwrap();
        let creds = shared.path().join("identity/credentials.json");
        fs::write(&creds, &original).unwrap();
        fs::create_dir_all(shared.path().join("Local")).unwrap();
        let hard = shared.path().join("Local/linked.bin");
        fs::hard_link(&creds, &hard).unwrap();
        let err = localhost_provider_bridge_config(shared.path(), &device_key).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("Local/linked.bin"), "{message}");
        assert!(message.contains(" is linked."), "{message}");
        assert_eq!(fs::read(&creds).unwrap(), original);
        assert_eq!(fs::read(&hard).unwrap(), original);
        assert!(!shared
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());
    }

    #[test]
    fn wrong_marker_content_stops_start_names_the_marker_and_leaves_files_unchanged() {
        let device_key = [0x44; 32];
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let original = localhost_provider::encrypt_bytes(&device_key, b"local-app secret").unwrap();
        fs::create_dir_all(root.join("Users")).unwrap();
        fs::write(root.join("Users/note.bin"), &original).unwrap();
        fs::create_dir_all(root.join("identity")).unwrap();
        let marker = root.join("identity/localhost-file-key-v1");
        fs::write(&marker, b"elastos-localhost-file-v2\n").unwrap();

        let err = localhost_provider_bridge_config(root, &device_key).unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("identity/localhost-file-key-v1"),
            "{message}"
        );
        assert!(message.contains("is not the migration record"), "{message}");
        assert_eq!(fs::read(root.join("Users/note.bin")).unwrap(), original);
        assert!(localhost_provider::decrypt_bytes(&device_key, &original).is_ok());
        assert_eq!(fs::read(&marker).unwrap(), b"elastos-localhost-file-v2\n");
        assert!(!root.join("identity/localhost-file-key.lock").exists());
        assert_no_localhost_rewrite_temps(root);
    }

    struct ClearLocalhostMigrationFaults;

    impl Drop for ClearLocalhostMigrationFaults {
        fn drop(&mut self) {
            set_localhost_migration_write_budget(None);
            set_localhost_migration_write_error(None);
            set_localhost_migration_create_error(None);
            set_localhost_migration_before_replace(None);
            set_localhost_migration_before_rename(None);
            set_localhost_migration_progress_clock(None);
            let _ = take_localhost_migration_bytes_read();
            let _ = take_localhost_migration_opens();
        }
    }

    fn assert_envelope_opens_with_exactly_one_key(
        path: &std::path::Path,
        plaintext: &[u8],
        device_key: &[u8; 32],
        file_key: &[u8; 32],
    ) {
        let bytes = fs::read(path).unwrap();
        let with_device = localhost_provider::decrypt_bytes(device_key, &bytes).ok();
        let with_file = localhost_provider::decrypt_bytes(file_key, &bytes).ok();
        match (with_device, with_file) {
            (Some(plain), None) | (None, Some(plain)) => assert_eq!(plain.as_slice(), plaintext),
            _ => panic!(
                "{} is readable under both keys or under neither",
                path.display()
            ),
        }
    }

    fn plant_device_envelope(
        path: &std::path::Path,
        device_key: &[u8; 32],
        plaintext: &[u8],
    ) -> Vec<u8> {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let sealed = localhost_provider::encrypt_bytes(device_key, plaintext).unwrap();
        fs::write(path, &sealed).unwrap();
        sealed
    }

    #[test]
    fn crash_at_every_migration_write_restarts_and_leaves_one_key() {
        let _clear = ClearLocalhostMigrationFaults;
        let device_key = [0x55; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let alpha = b"alpha-secret";
        let beta = b"beta-secret";
        let mut saw_fault = false;
        let mut finished_clean = false;
        for budget in 0..32 {
            let temp = TempDir::new().unwrap();
            let root = temp.path();
            let alpha_path = root.join("Users/alpha.bin");
            let beta_path = root.join("Local/beta.bin");
            plant_device_envelope(&alpha_path, &device_key, alpha);
            plant_device_envelope(&beta_path, &device_key, beta);
            fs::write(root.join("Users/readme.txt"), b"plain").unwrap();

            set_localhost_migration_write_budget(Some(budget));
            let first = localhost_provider_bridge_config(root, &device_key);
            set_localhost_migration_write_budget(None);
            if let Err(err) = first {
                saw_fault = true;
                assert!(err.to_string().contains("local apps stayed off"), "{err}");
                assert_envelope_opens_with_exactly_one_key(
                    &alpha_path,
                    alpha,
                    &device_key,
                    &file_key,
                );
                assert_envelope_opens_with_exactly_one_key(
                    &beta_path,
                    beta,
                    &device_key,
                    &file_key,
                );
                assert_eq!(fs::read(root.join("Users/readme.txt")).unwrap(), b"plain");
                let marker = root.join("identity/localhost-file-key-v1");
                if marker.exists() {
                    assert_current_marker(root, &device_key);
                    assert!(localhost_provider::decrypt_bytes(
                        &device_key,
                        &fs::read(&alpha_path).unwrap()
                    )
                    .is_err());
                    assert!(localhost_provider::decrypt_bytes(
                        &device_key,
                        &fs::read(&beta_path).unwrap()
                    )
                    .is_err());
                } else {
                    let temp_dir = root.join("identity/localhost-file-key-v1.tmpd");
                    fs::create_dir_all(&temp_dir).unwrap();
                    fs::write(temp_dir.join("partial.tmp"), b"partial").unwrap();
                }

                localhost_provider_bridge_config(root, &device_key).unwrap();
                assert_envelope_opens_with_exactly_one_key(
                    &alpha_path,
                    alpha,
                    &device_key,
                    &file_key,
                );
                assert_envelope_opens_with_exactly_one_key(
                    &beta_path,
                    beta,
                    &device_key,
                    &file_key,
                );
                assert!(localhost_provider::decrypt_bytes(
                    &device_key,
                    &fs::read(&alpha_path).unwrap()
                )
                .is_err());
                assert!(localhost_provider::decrypt_bytes(
                    &device_key,
                    &fs::read(&beta_path).unwrap()
                )
                .is_err());
                assert_current_marker(root, &device_key);
                assert_eq!(fs::read(root.join("Users/readme.txt")).unwrap(), b"plain");
                assert_no_localhost_rewrite_temps(root);
            } else {
                finished_clean = true;
                assert_envelope_opens_with_exactly_one_key(
                    &alpha_path,
                    alpha,
                    &device_key,
                    &file_key,
                );
                assert_envelope_opens_with_exactly_one_key(
                    &beta_path,
                    beta,
                    &device_key,
                    &file_key,
                );
                assert!(localhost_provider::decrypt_bytes(
                    &device_key,
                    &fs::read(&alpha_path).unwrap()
                )
                .is_err());
                assert!(localhost_provider::decrypt_bytes(
                    &device_key,
                    &fs::read(&beta_path).unwrap()
                )
                .is_err());
                assert_current_marker(root, &device_key);
                assert_eq!(fs::read(root.join("Users/readme.txt")).unwrap(), b"plain");
                assert_no_localhost_rewrite_temps(root);
                break;
            }
        }
        assert!(saw_fault, "no write failed");
        assert!(finished_clean, "a full budget never finished the migration");
    }

    fn spawn_migration_child(
        root: &std::path::Path,
        device_key: &[u8; 32],
        ready_name: &str,
    ) -> std::process::Child {
        use std::process::{Command, Stdio};

        let test = format!(
            "{}::localhost_migration_second_home_child",
            module_path!().split_once("::").unwrap().1
        );
        Command::new(std::env::current_exe().unwrap())
            .env("ELASTOS_LOCALHOST_MIGRATION_CHILD_ROOT", root)
            .env(
                "ELASTOS_LOCALHOST_MIGRATION_CHILD_KEY",
                hex::encode(device_key),
            )
            .env("ELASTOS_LOCALHOST_MIGRATION_CHILD_READY", ready_name)
            .env(
                "ELASTOS_LOCALHOST_MIGRATION_WAIT_PROBE",
                root.join(ready_name),
            )
            .args([
                "--exact",
                test.as_str(),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    struct ReapChild(Option<std::process::Child>);

    impl Drop for ReapChild {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                if matches!(child.try_wait(), Ok(None)) {
                    let _ = child.kill();
                }
                let _ = child.wait();
            }
        }
    }

    impl ReapChild {
        fn spawn(root: &std::path::Path, device_key: &[u8; 32], ready_name: &str) -> Self {
            Self(Some(spawn_migration_child(root, device_key, ready_name)))
        }

        fn child(&mut self) -> &mut std::process::Child {
            self.0.as_mut().unwrap()
        }
    }

    fn child_output(child: &mut std::process::Child) -> (String, String) {
        use std::io::Read;

        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            pipe.read_to_string(&mut stdout).unwrap();
        }
        if let Some(mut pipe) = child.stderr.take() {
            pipe.read_to_string(&mut stderr).unwrap();
        }
        (stdout, stderr)
    }

    #[test]
    fn two_homes_on_one_data_folder_finish_on_one_key() {
        use std::time::{Duration, Instant};

        let device_key = [0x66; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let plaintext = b"shared-home-secret";

        let blocked = TempDir::new().unwrap();
        let blocked_root = blocked.path();
        let blocked_note = blocked_root.join("Users/note.bin");
        plant_device_envelope(&blocked_note, &device_key, plaintext);
        let _lock = hold_localhost_migration_lock(blocked_root).unwrap();
        let mut child = ReapChild::spawn(blocked_root, &device_key, "child-hold");
        let ready = blocked_root.join("child-hold");
        let done = ready.with_extension("done");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "second Home did not reach the migration lock"
            );
            if let Some(status) = child.child().try_wait().unwrap() {
                let (stdout, stderr) = child_output(child.child());
                panic!(
                    "second Home exited before waiting: {status} stdout {stdout} stderr {stderr}"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read(&ready).unwrap(), b"waiting");
        assert!(
            child.child().try_wait().unwrap().is_none(),
            "second Home ran while the first Home held the migration lock"
        );
        assert!(!done.exists());
        assert_eq!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&blocked_note).unwrap())
                .unwrap(),
            plaintext
        );
        drop(_lock);
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.child().try_wait().unwrap() {
                let (stdout, stderr) = child_output(child.child());
                assert!(
                    status.success(),
                    "second Home failed: {status} stdout {stdout} stderr {stderr}"
                );
                assert!(
                    stderr.contains("localhost file migration is waiting"),
                    "{stderr}"
                );
                break;
            }
            assert!(Instant::now() < deadline, "second Home did not finish");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_envelope_opens_with_exactly_one_key(
            &blocked_note,
            plaintext,
            &device_key,
            &file_key,
        );
        assert!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&blocked_note).unwrap())
                .is_err()
        );
        assert_eq!(fs::read(&done).unwrap(), hex::encode(file_key).into_bytes());

        let shared = TempDir::new().unwrap();
        let shared_root = shared.path();
        let first = shared_root.join("Users/one.bin");
        let second = shared_root.join("Users/two.bin");
        plant_device_envelope(&first, &device_key, b"one");
        plant_device_envelope(&second, &device_key, b"two");
        let mut home_a = ReapChild::spawn(shared_root, &device_key, "child-a");
        let mut home_b = ReapChild::spawn(shared_root, &device_key, "child-b");
        for (name, child) in [("Home A", home_a.child()), ("Home B", home_b.child())] {
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let (stdout, stderr) = child_output(child);
                    assert!(
                        status.success(),
                        "{name} failed: {status} stdout {stdout} stderr {stderr}"
                    );
                    break;
                }
                assert!(Instant::now() < deadline, "{name} did not finish");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        assert_envelope_opens_with_exactly_one_key(&first, b"one", &device_key, &file_key);
        assert_envelope_opens_with_exactly_one_key(&second, b"two", &device_key, &file_key);
        let done_a = fs::read(shared_root.join("child-a.done")).unwrap();
        let done_b = fs::read(shared_root.join("child-b.done")).unwrap();
        assert_eq!(done_a, hex::encode(file_key).into_bytes());
        assert_eq!(done_b, hex::encode(file_key).into_bytes());
        assert!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&first).unwrap()).is_err()
        );
        assert_current_marker(shared_root, &device_key);
        assert_no_localhost_rewrite_temps(shared_root);
    }

    #[test]
    #[ignore]
    fn localhost_migration_second_home_child() {
        let Ok(root) = std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_ROOT") else {
            return;
        };
        let key_hex = std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_KEY").unwrap();
        let ready_name = std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_READY").unwrap();
        let bytes = hex::decode(key_hex).unwrap();
        let mut device_key = [0u8; 32];
        device_key.copy_from_slice(&bytes);
        let root = std::path::PathBuf::from(root);
        let _log = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
        let ready = root.join(ready_name);
        let config = localhost_provider_bridge_config(&root, &device_key).unwrap();
        fs::write(
            ready.with_extension("done"),
            config.encryption_key.as_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn symlink_root_marker_identity_and_inside_hard_link_stop_start() {
        use std::os::unix::fs::symlink;

        let device_key = [0x73; 32];
        let original = localhost_provider::encrypt_bytes(&device_key, b"linked-secret").unwrap();

        let outside = TempDir::new().unwrap();
        let linked_root = TempDir::new().unwrap();
        fs::create_dir(outside.path().join("real-users")).unwrap();
        fs::write(outside.path().join("real-users/note.bin"), &original).unwrap();
        symlink(
            outside.path().join("real-users"),
            linked_root.path().join("Users"),
        )
        .unwrap();
        let err = localhost_provider_bridge_config(linked_root.path(), &device_key).unwrap_err();
        assert!(err.to_string().contains("Users is linked."), "{err}");
        assert!(err.to_string().contains(" is linked."), "{err}");
        assert_eq!(
            fs::read(outside.path().join("real-users/note.bin")).unwrap(),
            original
        );
        assert!(!linked_root
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());

        let marker_root = TempDir::new().unwrap();
        plant_device_envelope(
            &marker_root.path().join("Users/note.bin"),
            &device_key,
            b"linked-secret",
        );
        fs::create_dir(marker_root.path().join("identity")).unwrap();
        let marker_target = outside.path().join("marker-target");
        fs::write(&marker_target, b"not-the-record").unwrap();
        let marker = marker_root.path().join("identity/localhost-file-key-v1");
        symlink(&marker_target, &marker).unwrap();
        let err = localhost_provider_bridge_config(marker_root.path(), &device_key).unwrap_err();
        assert!(
            err.to_string().contains("identity/localhost-file-key-v1"),
            "{err}"
        );
        assert!(err.to_string().contains(" is linked."), "{err}");
        assert_eq!(fs::read(&marker_target).unwrap(), b"not-the-record");
        assert_eq!(
            localhost_provider::decrypt_bytes(
                &device_key,
                &fs::read(marker_root.path().join("Users/note.bin")).unwrap()
            )
            .unwrap(),
            b"linked-secret"
        );

        let identity_root = TempDir::new().unwrap();
        plant_device_envelope(
            &identity_root.path().join("Local/note.bin"),
            &device_key,
            b"linked-secret",
        );
        let identity_target = outside.path().join("ident");
        fs::create_dir(&identity_target).unwrap();
        symlink(&identity_target, identity_root.path().join("identity")).unwrap();
        let err = localhost_provider_bridge_config(identity_root.path(), &device_key).unwrap_err();
        assert!(err.to_string().contains(" is linked."), "{err}");
        assert!(fs::read_dir(&identity_target).unwrap().next().is_none());
        assert_eq!(
            localhost_provider::decrypt_bytes(
                &device_key,
                &fs::read(identity_root.path().join("Local/note.bin")).unwrap()
            )
            .unwrap(),
            b"linked-secret"
        );

        let hard = TempDir::new().unwrap();
        let hard_a = hard.path().join("Users/a.bin");
        let sealed = plant_device_envelope(&hard_a, &device_key, b"linked-secret");
        let hard_b = hard.path().join("Users/b.bin");
        fs::hard_link(&hard_a, &hard_b).unwrap();
        let err = localhost_provider_bridge_config(hard.path(), &device_key).unwrap_err();
        assert!(err.to_string().contains(" is linked."), "{err}");
        assert_eq!(fs::read(&hard_a).unwrap(), sealed);
        assert_eq!(fs::read(&hard_b).unwrap(), sealed);
        assert!(!hard.path().join("identity/localhost-file-key-v1").exists());

        let lock_link = TempDir::new().unwrap();
        plant_device_envelope(
            &lock_link.path().join("Users/note.bin"),
            &device_key,
            b"linked-secret",
        );
        fs::create_dir(lock_link.path().join("identity")).unwrap();
        let creds = lock_link.path().join("identity/credentials.json");
        fs::write(&creds, &original).unwrap();
        fs::hard_link(
            &creds,
            lock_link.path().join("identity/localhost-file-key.lock"),
        )
        .unwrap();
        let err = localhost_provider_bridge_config(lock_link.path(), &device_key).unwrap_err();
        assert!(err.to_string().contains("localhost-file-key.lock"), "{err}");
        assert!(err.to_string().contains(" is linked."), "{err}");
        assert_eq!(fs::read(&creds).unwrap(), original);
        assert_eq!(
            localhost_provider::decrypt_bytes(
                &device_key,
                &fs::read(lock_link.path().join("Users/note.bin")).unwrap()
            )
            .unwrap(),
            b"linked-secret"
        );
    }

    #[test]
    fn large_localhost_tree_migrates_once_and_second_start_does_not_rewrite() {
        let device_key = [0x77; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let count = 1000;
        for index in 0..count {
            let plaintext = format!("bulk-{index}");
            plant_device_envelope(
                &root.join(format!("Users/bulk/f{index:04}.bin")),
                &device_key,
                plaintext.as_bytes(),
            );
        }
        fs::create_dir_all(root.join("Users/bulk/nested")).unwrap();
        for index in 0..10 {
            plant_device_envelope(
                &root.join(format!("Users/bulk/nested/n{index}.bin")),
                &device_key,
                b"nested",
            );
        }
        fs::write(root.join("Users/bulk/plain.txt"), b"leave-me").unwrap();

        let config = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(config.encryption_key, hex::encode(file_key));
        for index in [0, 1, count - 1] {
            let plaintext = format!("bulk-{index}");
            let path = root.join(format!("Users/bulk/f{index:04}.bin"));
            assert_envelope_opens_with_exactly_one_key(
                &path,
                plaintext.as_bytes(),
                &device_key,
                &file_key,
            );
        }
        assert_envelope_opens_with_exactly_one_key(
            &root.join("Users/bulk/nested/n0.bin"),
            b"nested",
            &device_key,
            &file_key,
        );
        assert_eq!(
            fs::read(root.join("Users/bulk/plain.txt")).unwrap(),
            b"leave-me"
        );
        let sample = fs::read(root.join("Users/bulk/f0000.bin")).unwrap();
        let tail =
            fs::read(root.join(format!("Users/bulk/f{index:04}.bin", index = count - 1))).unwrap();
        let again = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(again.encryption_key, hex::encode(file_key));
        assert_eq!(fs::read(root.join("Users/bulk/f0000.bin")).unwrap(), sample);
        assert_eq!(
            fs::read(root.join(format!("Users/bulk/f{index:04}.bin", index = count - 1))).unwrap(),
            tail
        );
        assert_current_marker(root, &device_key);
        assert_no_localhost_rewrite_temps(root);
    }

    #[test]
    fn file_changed_during_the_walk_keeps_the_new_bytes_and_stops_start() {
        let _clear = ClearLocalhostMigrationFaults;
        let device_key = [0x79; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let alpha = root.join("Users/a.bin");
        let beta = root.join("Users/b.bin");
        plant_device_envelope(&alpha, &device_key, b"alpha");
        let original_beta = plant_device_envelope(&beta, &device_key, b"beta");
        set_localhost_migration_before_replace(Some(Box::new(move |path: &std::path::Path| {
            if path.file_name().and_then(|name| name.to_str()) != Some("b.bin") {
                return;
            }
            let sealed =
                localhost_provider::encrypt_bytes(&device_key, b"changed-during-walk").unwrap();
            let swap = path.with_file_name(".b.bin.swap");
            fs::write(&swap, &sealed).unwrap();
            fs::rename(&swap, path).unwrap();
        })));
        let err = localhost_provider_bridge_config(root, &device_key).unwrap_err();
        set_localhost_migration_before_replace(None);
        assert!(err.to_string().contains("changed while read"), "{err}");
        assert!(err.to_string().contains("b.bin"), "{err}");
        assert_ne!(fs::read(&beta).unwrap(), original_beta);
        assert_eq!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&beta).unwrap()).unwrap(),
            b"changed-during-walk"
        );
        assert_envelope_opens_with_exactly_one_key(&alpha, b"alpha", &device_key, &file_key);
        assert!(!root.join("identity/localhost-file-key-v1").exists());
        let alpha_bytes = fs::read(&alpha).unwrap();

        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(fs::read(&alpha).unwrap(), alpha_bytes);
        assert_envelope_opens_with_exactly_one_key(
            &beta,
            b"changed-during-walk",
            &device_key,
            &file_key,
        );
        assert!(localhost_provider::decrypt_bytes(&device_key, &fs::read(&beta).unwrap()).is_err());
        assert_current_marker(root, &device_key);
        assert_no_localhost_rewrite_temps(root);
    }

    #[test]
    fn file_swapped_after_the_temp_sync_keeps_the_new_bytes() {
        let _clear = ClearLocalhostMigrationFaults;
        let device_key = [0x78; 32];
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let note = root.join("Users/late.bin");
        let original = plant_device_envelope(&note, &device_key, b"before");
        set_localhost_migration_before_rename(Some(Box::new(move |path: &std::path::Path| {
            if path.file_name().and_then(|name| name.to_str()) != Some("late.bin") {
                return;
            }
            let sealed = localhost_provider::encrypt_bytes(&device_key, b"after-sync").unwrap();
            let swap = path.with_file_name(".late.bin.swap");
            fs::write(&swap, &sealed).unwrap();
            fs::rename(&swap, path).unwrap();
        })));
        let err = localhost_provider_bridge_config(root, &device_key).unwrap_err();
        set_localhost_migration_before_rename(None);
        let text = err.to_string();
        assert!(text.contains("changed while read"), "{text}");
        assert!(text.contains("Users/late.bin"), "{text}");
        assert!(!text.contains("could not be written"), "{text}");
        assert_ne!(fs::read(&note).unwrap(), original);
        assert_eq!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&note).unwrap()).unwrap(),
            b"after-sync"
        );
        assert!(!root.join("identity/localhost-file-key-v1").exists());
        assert_no_localhost_rewrite_temps(root);
    }

    #[test]
    fn raw_device_key_is_not_used_again_after_migration() {
        let device_key = [0x7a; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let note = root.join("Users/note.bin");
        plant_device_envelope(&note, &device_key, b"already-moved");
        let config = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(config.encryption_key, hex::encode(file_key));
        assert_ne!(config.encryption_key, hex::encode(device_key));
        let migrated = fs::read(&note).unwrap();
        assert!(localhost_provider::decrypt_bytes(&device_key, &migrated).is_err());
        assert_eq!(
            localhost_provider::decrypt_bytes(&file_key, &migrated).unwrap(),
            b"already-moved"
        );

        let later = localhost_provider::encrypt_bytes(&device_key, b"written-after").unwrap();
        fs::create_dir_all(root.join("Local")).unwrap();
        fs::write(root.join("Local/later.bin"), &later).unwrap();
        let again = localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(again.encryption_key, hex::encode(file_key));
        assert_ne!(fs::read(root.join("Local/later.bin")).unwrap(), later);
        assert_eq!(
            localhost_provider::decrypt_bytes(
                &file_key,
                &fs::read(root.join("Local/later.bin")).unwrap()
            )
            .unwrap(),
            b"written-after"
        );
        assert!(localhost_provider::decrypt_bytes(
            &device_key,
            &fs::read(root.join("Local/later.bin")).unwrap()
        )
        .is_err());
        assert_eq!(fs::read(&note).unwrap(), migrated);
        assert_current_marker(root, &device_key);
    }

    struct LocalAppsGuard(std::sync::MutexGuard<'static, ()>);

    impl LocalAppsGuard {
        fn lock() -> Self {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let guard = Self(LOCK.lock().unwrap_or_else(|err| err.into_inner()));
            elastos_server::local_apps::begin_local_apps_guard();
            guard
        }
    }

    impl Drop for LocalAppsGuard {
        fn drop(&mut self) {
            let _kept = &self.0;
            elastos_server::local_apps::end_local_apps_guard();
        }
    }

    fn home_stays_up(root: &std::path::Path, sentence: &str) {
        assert_eq!(
            elastos_server::local_apps::local_apps_refusal(root).as_deref(),
            Some(sentence)
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let body = elastos_server::api::routes::health().await;
            assert_eq!(serde_json::to_value(body.0).unwrap()["status"], "ok");
            let provider =
                elastos_server::local_apps::RefusingLocalhostProvider::new(sentence.to_string());
            match elastos_runtime::provider::Provider::send_raw(&provider, &serde_json::json!({}))
                .await
                .unwrap_err()
            {
                provider::ProviderError::Provider(text) => {
                    assert_eq!(
                        elastos_server::local_apps::sentence_from_local_apps_provider_error(&text),
                        Some(sentence)
                    );
                }
                other => panic!("{other}"),
            }
        });
    }

    fn expect_refusal(
        root: &std::path::Path,
        device_key: &[u8; 32],
        sentence: &str,
        marker_absent: bool,
    ) {
        match localhost_bringup(root, device_key) {
            LocalhostBringup::Refuse(got) => assert_eq!(got, sentence),
            LocalhostBringup::Start(_) => panic!("local apps started for {sentence}"),
        }
        home_stays_up(root, sentence);
        if marker_absent {
            assert!(!root.join("identity/localhost-file-key-v1").exists());
        }
    }

    #[test]
    fn a_bad_file_in_one_home_does_not_turn_off_another() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = LocalAppsGuard::lock();
        let bad_key = [0x31; 32];
        let good_key = [0x32; 32];
        let bad = TempDir::new().unwrap();
        let good = TempDir::new().unwrap();
        let secret = bad.path().join("Users/secret.bin");
        let original = plant_device_envelope(&secret, &bad_key, b"hidden");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
        let note = good.path().join("Users/note.bin");
        plant_device_envelope(&note, &good_key, b"visible");

        let bad_sentence = match localhost_bringup(bad.path(), &bad_key) {
            LocalhostBringup::Refuse(sentence) => sentence,
            LocalhostBringup::Start(_) => panic!("the bad Home started local apps"),
        };
        assert!(bad_sentence.contains("Users/secret.bin"), "{bad_sentence}");
        assert!(bad_sentence.contains("not readable"), "{bad_sentence}");
        match localhost_bringup(good.path(), &good_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => panic!("the good Home was turned off: {got}"),
        }
        assert_eq!(
            elastos_server::local_apps::local_apps_refusal(bad.path()).as_deref(),
            Some(bad_sentence.as_str())
        );
        assert!(elastos_server::local_apps::local_apps_refusal(good.path()).is_none());

        let bad_registry = Arc::new(provider::ProviderRegistry::new());
        let good_registry = Arc::new(provider::ProviderRegistry::new());
        let storage = |registry, data_dir: &std::path::Path| {
            elastos_server::api::handlers::storage::ProviderStorageState {
                data_dir: data_dir.to_path_buf(),
                registry,
                audit_log: None,
                capability_manager: None,
                storage_quota_mb: 0,
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let session =
                || axum::Extension(session::Session::new(session::SessionType::Shell, None));
            let path = || axum::extract::Path("MyWebSite/index.html".to_string());
            let bad_route = elastos_server::api::handlers::storage::read_file(
                axum::extract::State(storage(bad_registry, bad.path())),
                session(),
                axum::http::HeaderMap::new(),
                path(),
            )
            .await;
            match bad_route {
                Err(elastos_server::api::handlers::storage::StorageApiError::LocalApps(got)) => {
                    assert_eq!(got, bad_sentence);
                }
                other => panic!("bad Home route: {other:?}"),
            }
            let good_route = elastos_server::api::handlers::storage::read_file(
                axum::extract::State(storage(good_registry, good.path())),
                session(),
                axum::http::HeaderMap::new(),
                path(),
            )
            .await;
            if let Err(elastos_server::api::handlers::storage::StorageApiError::LocalApps(got)) =
                good_route
            {
                panic!("good Home route was turned off: {got}");
            }
        });

        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&secret).unwrap(), original);
        assert!(!bad.path().join("identity/localhost-file-key-v1").exists());
        assert_envelope_opens_with_exactly_one_key(
            &note,
            b"visible",
            &good_key,
            &expected_localhost_file_key(&good_key),
        );
    }

    fn migrate_again(root: &std::path::Path, device_key: &[u8; 32]) {
        match localhost_bringup(root, device_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => panic!("{got}"),
        }
    }

    fn sentence(relative: &str, cause: &str) -> String {
        let remedy = match cause {
            "not readable" => "Make it readable, then restart.",
            "linked" => "Replace the link with a regular file, then restart.",
            "changed while read" => "Leave it unchanged, then restart.",
            "not decryptable" => "Remove it, then restart.",
            "not a regular file" => "Replace it with a regular file, then restart.",
            "larger than this process can read" => "Move it out of the folder, then restart.",
            other => panic!("no remedy for {other}"),
        };
        format!("{relative} is {cause}. {remedy}")
    }

    fn home_is_up(root: &std::path::Path) {
        assert!(elastos_server::local_apps::local_apps_refusal(root).is_none());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let body = elastos_server::api::routes::health().await;
            assert_eq!(serde_json::to_value(body.0).unwrap()["status"], "ok");
        });
    }

    fn assert_read_refused_by_name(path: &std::path::Path, key: &[u8; 32], name: &str) {
        let err = localhost_provider::read_sealed_localhost_file(key, path, name).unwrap_err();
        let text = err.to_string();
        assert!(text.contains(name), "{text}");
        assert!(text.contains("larger than 32 MiB"), "{text}");
    }

    #[test]
    fn each_migration_cause_keeps_home_healthy_and_a_restart_migrates() {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        let _guard = LocalAppsGuard::lock();
        let device_key = [0x91; 32];
        let file_key = expected_localhost_file_key(&device_key);

        let unread = TempDir::new().unwrap();
        let secret = unread.path().join("Users/secret.bin");
        let original = plant_device_envelope(&secret, &device_key, b"hidden");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
        expect_refusal(
            unread.path(),
            &device_key,
            &sentence("Users/secret.bin", "not readable"),
            true,
        );
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&secret).unwrap(), original);
        match localhost_bringup(unread.path(), &device_key) {
            LocalhostBringup::Start(config) => {
                assert_eq!(config.encryption_key, hex::encode(file_key));
            }
            LocalhostBringup::Refuse(got) => panic!("{got}"),
        }
        assert!(elastos_server::local_apps::local_apps_refusal(unread.path()).is_none());
        assert_envelope_opens_with_exactly_one_key(&secret, b"hidden", &device_key, &file_key);
        assert_current_marker(unread.path(), &device_key);

        let linked = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let creds = outside.path().join("cred.bin");
        fs::write(&creds, b"outside").unwrap();
        fs::create_dir_all(linked.path().join("Users")).unwrap();
        std::os::unix::fs::symlink(&creds, linked.path().join("Users/alias.json")).unwrap();
        expect_refusal(
            linked.path(),
            &device_key,
            &sentence("Users/alias.json", "linked"),
            true,
        );
        assert_eq!(fs::read(&creds).unwrap(), b"outside");
        fs::remove_file(linked.path().join("Users/alias.json")).unwrap();
        let alias = linked.path().join("Users/alias.json");
        plant_device_envelope(&alias, &device_key, b"alias");
        migrate_again(linked.path(), &device_key);
        assert_envelope_opens_with_exactly_one_key(&alias, b"alias", &device_key, &file_key);

        let changed = TempDir::new().unwrap();
        let _clear = ClearLocalhostMigrationFaults;
        let beta = changed.path().join("Users/b.bin");
        plant_device_envelope(&changed.path().join("Users/a.bin"), &device_key, b"alpha");
        plant_device_envelope(&beta, &device_key, b"beta");
        set_localhost_migration_before_replace(Some(Box::new(move |path: &std::path::Path| {
            if path.file_name().and_then(|name| name.to_str()) != Some("b.bin") {
                return;
            }
            let sealed =
                localhost_provider::encrypt_bytes(&device_key, b"changed-during-walk").unwrap();
            let swap = path.with_file_name(".b.bin.swap");
            fs::write(&swap, &sealed).unwrap();
            fs::rename(&swap, path).unwrap();
        })));
        expect_refusal(
            changed.path(),
            &device_key,
            &sentence("Users/b.bin", "changed while read"),
            true,
        );
        set_localhost_migration_before_replace(None);
        assert_eq!(
            localhost_provider::decrypt_bytes(&device_key, &fs::read(&beta).unwrap()).unwrap(),
            b"changed-during-walk"
        );
        migrate_again(changed.path(), &device_key);
        assert_envelope_opens_with_exactly_one_key(
            &beta,
            b"changed-during-walk",
            &device_key,
            &file_key,
        );

        let foreign = TempDir::new().unwrap();
        let bad = foreign.path().join("Users/bad.bin");
        let sealed = localhost_provider::encrypt_bytes(&[0x42; 32], b"other").unwrap();
        fs::create_dir_all(bad.parent().unwrap()).unwrap();
        fs::write(&bad, &sealed).unwrap();
        expect_refusal(
            foreign.path(),
            &device_key,
            &sentence("Users/bad.bin", "not decryptable"),
            true,
        );
        assert_eq!(fs::read(&bad).unwrap(), sealed);
        fs::remove_file(&bad).unwrap();
        plant_device_envelope(&bad, &device_key, b"fixed");
        migrate_again(foreign.path(), &device_key);
        assert_envelope_opens_with_exactly_one_key(&bad, b"fixed", &device_key, &file_key);

        let huge = TempDir::new().unwrap();
        let big = huge.path().join("Users/big.bin");
        fs::create_dir_all(big.parent().unwrap()).unwrap();
        fs::write(&big, b"plain-video").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&big)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        migrate_again(huge.path(), &device_key);
        assert!(fs::read(&big).unwrap().starts_with(b"plain-video"));
        assert_eq!(fs::metadata(&big).unwrap().len(), 32 * 1024 * 1024 + 1);
        let over = huge.path().join("Users/over.bin");
        let envelope = localhost_provider::encrypt_bytes(&device_key, b"too-big").unwrap();
        fs::write(&over, &envelope).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&over)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        migrate_again(huge.path(), &device_key);
        let read = take_localhost_migration_bytes_read();
        let opens = take_localhost_migration_opens();
        assert!(
            read > 32 * 1024 * 1024,
            "the new over-cap file was not read: {read}"
        );
        assert_eq!(opens, 1, "a settled file was opened: {opens}");
        home_is_up(huge.path());
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        migrate_again(huge.path(), &device_key);
        assert_eq!(take_localhost_migration_bytes_read(), 0);
        assert_eq!(take_localhost_migration_opens(), 0);
        assert_read_refused_by_name(&over, &file_key, "Users/over.bin");
        assert_read_refused_by_name(&big, &file_key, "Users/big.bin");
        assert_eq!(fs::metadata(&over).unwrap().len(), 32 * 1024 * 1024 + 1);
        let mut prefix = vec![0u8; envelope.len()];
        std::io::Read::read_exact(&mut std::fs::File::open(&over).unwrap(), &mut prefix).unwrap();
        assert_eq!(prefix, envelope);
        let small = huge.path().join("Users/small.bin");
        plant_device_envelope(&small, &device_key, b"small");
        migrate_again(huge.path(), &device_key);
        assert_envelope_opens_with_exactly_one_key(&small, b"small", &device_key, &file_key);
        assert_eq!(
            localhost_provider::read_sealed_localhost_file(&file_key, &small, "Users/small.bin")
                .unwrap(),
            b"small"
        );
        assert!(fs::read(&big).unwrap().starts_with(b"plain-video"));
        home_is_up(huge.path());

        let fifo_root = TempDir::new().unwrap();
        let pipe = fifo_root.path().join("Users/pipe");
        fs::create_dir_all(pipe.parent().unwrap()).unwrap();
        let c_path = CString::new(pipe.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        expect_refusal(
            fifo_root.path(),
            &device_key,
            &sentence("Users/pipe", "not a regular file"),
            true,
        );
        assert!(fs::symlink_metadata(&pipe).unwrap().file_type().is_fifo());
        fs::remove_file(&pipe).unwrap();
        plant_device_envelope(&pipe, &device_key, b"was-fifo");
        migrate_again(fifo_root.path(), &device_key);
        assert_envelope_opens_with_exactly_one_key(&pipe, b"was-fifo", &device_key, &file_key);
    }

    #[test]
    fn marker_fingerprint_covers_downgrade_restore_forge_and_copy() {
        let _guard = LocalAppsGuard::lock();
        let device_key = [0x92; 32];
        let other_key = [0x93; 32];
        let file_key = expected_localhost_file_key(&device_key);

        let downgrade = TempDir::new().unwrap();
        let note = downgrade.path().join("Users/note.bin");
        plant_device_envelope(&note, &device_key, b"first");
        localhost_provider_bridge_config(downgrade.path(), &device_key).unwrap();
        fs::write(
            downgrade.path().join("identity/localhost-file-key-v1"),
            b"elastos-localhost-file-v1\n",
        )
        .unwrap();
        let later = localhost_provider::encrypt_bytes(&device_key, b"from-old-build").unwrap();
        fs::write(downgrade.path().join("Users/later.bin"), &later).unwrap();
        localhost_provider_bridge_config(downgrade.path(), &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(
            &downgrade.path().join("Users/later.bin"),
            b"from-old-build",
            &device_key,
            &file_key,
        );
        assert_envelope_opens_with_exactly_one_key(&note, b"first", &device_key, &file_key);
        assert_current_marker(downgrade.path(), &device_key);

        let restored = TempDir::new().unwrap();
        let kept = restored.path().join("Users/note.bin");
        plant_device_envelope(&kept, &device_key, b"restored");
        localhost_provider_bridge_config(restored.path(), &device_key).unwrap();
        let before = fs::read(&kept).unwrap();
        let marker_before =
            fs::read(restored.path().join("identity/localhost-file-key-v1")).unwrap();
        let mismatch = "identity/localhost-file-key-v1 does not match this Home (restored or copied folder, changed device key). Restore the matching identity/device.key, or move AppCapsules, ElastOS, Local, Users, and UsersAI aside to start empty, then restart.".to_string();
        expect_refusal(restored.path(), &other_key, &mismatch, false);
        assert_eq!(fs::read(&kept).unwrap(), before);
        assert_eq!(
            fs::read(restored.path().join("identity/localhost-file-key-v1")).unwrap(),
            marker_before
        );

        let forged = TempDir::new().unwrap();
        let forged_note = forged.path().join("Users/note.bin");
        let forged_bytes = plant_device_envelope(&forged_note, &device_key, b"forged");
        fs::create_dir_all(forged.path().join("identity")).unwrap();
        fs::write(
            forged.path().join("identity/localhost-file-key-v1"),
            b"elastos-localhost-file-v1 9 aa\n",
        )
        .unwrap();
        expect_refusal(
            forged.path(),
            &device_key,
            "identity/localhost-file-key-v1 is not the migration record. Delete identity/localhost-file-key-v1, then restart.",
            false,
        );
        assert_eq!(fs::read(&forged_note).unwrap(), forged_bytes);
        assert!(!forged
            .path()
            .join("identity/localhost-file-key.lock")
            .exists());

        let source = TempDir::new().unwrap();
        plant_device_envelope(
            &source.path().join("Users/note.bin"),
            &device_key,
            b"source",
        );
        localhost_provider_bridge_config(source.path(), &device_key).unwrap();
        let copied = fs::read(source.path().join("identity/localhost-file-key-v1")).unwrap();
        let dest = TempDir::new().unwrap();
        let dest_note = dest.path().join("Users/note.bin");
        let dest_bytes = plant_device_envelope(&dest_note, &other_key, b"dest");
        fs::create_dir_all(dest.path().join("identity")).unwrap();
        fs::write(dest.path().join("identity/localhost-file-key-v1"), &copied).unwrap();
        expect_refusal(dest.path(), &other_key, &mismatch, false);
        assert_eq!(fs::read(&dest_note).unwrap(), dest_bytes);
        assert_eq!(
            localhost_provider::decrypt_bytes(&other_key, &dest_bytes).unwrap(),
            b"dest"
        );
        assert!(!dest
            .path()
            .join("identity/localhost-file-key.lock")
            .exists());
    }

    #[test]
    fn startup_decides_the_marker_before_it_recreates_the_five_roots() {
        let _guard = LocalAppsGuard::lock();
        let old_key = [0xc1; 32];
        let new_key = [0xc2; 32];
        let old_file_key = expected_localhost_file_key(&old_key);
        let root = TempDir::new().unwrap();
        let note = root.path().join("Users/note.bin");
        plant_device_envelope(&note, &old_key, b"kept");
        localhost_provider_bridge_config(root.path(), &old_key).unwrap();
        let sealed = fs::read(&note).unwrap();
        plant_device_key(root.path(), &new_key);
        fs::set_permissions(
            root.path().join("identity/device.key"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let aside = root.path().join("Users.aside");
        fs::rename(root.path().join("Users"), &aside).unwrap();
        crate::localhost_file_migration::prepare_localhost_files(root.path()).unwrap();
        assert_current_marker(root.path(), &new_key);
        assert!(!root.path().join("Users").exists());
        ensure_file_backed_roots(root.path()).unwrap();
        let auth = root.path().join("ElastOS/System/Auth");
        fs::create_dir_all(&auth).unwrap();
        let lock = auth.join("audit-chain-required.json.lock");
        fs::write(&lock, b"lock").unwrap();
        match localhost_bringup(root.path(), &new_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => {
                panic!("startup recreated the roots before the marker decision: {got}")
            }
        }
        home_is_up(root.path());
        assert_current_marker(root.path(), &new_key);
        assert_eq!(fs::read(&lock).unwrap(), b"lock");
        assert_eq!(fs::read(aside.join("note.bin")).unwrap(), sealed);
        assert_eq!(
            localhost_provider::decrypt_bytes(&old_file_key, &sealed).unwrap(),
            b"kept"
        );

        let left = TempDir::new().unwrap();
        plant_device_key(left.path(), &new_key);
        fs::create_dir_all(left.path().join("Users")).unwrap();
        let marker_path = left.path().join("identity/localhost-file-key-v1");
        fs::write(
            &marker_path,
            crate::localhost_file_migration::localhost_marker_record(&expected_localhost_file_key(
                &old_key,
            )),
        )
        .unwrap();
        let marker_before = fs::read(&marker_path).unwrap();
        crate::localhost_file_migration::prepare_localhost_files(left.path()).unwrap();
        ensure_file_backed_roots(left.path()).unwrap();
        match localhost_bringup(left.path(), &new_key) {
            LocalhostBringup::Refuse(got) => {
                assert!(got.contains("does not match this Home"), "{got}");
            }
            LocalhostBringup::Start(_) => panic!("an empty root left in place started empty"),
        }
        assert_eq!(fs::read(&marker_path).unwrap(), marker_before);
    }

    #[test]
    fn mismatch_remedies_restore_the_key_or_start_empty() {
        let _guard = LocalAppsGuard::lock();
        let device_key = [0xb1; 32];
        let other_key = [0xb2; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let root = TempDir::new().unwrap();
        let note = root.path().join("Users/note.bin");
        plant_device_envelope(&note, &device_key, b"kept");
        localhost_provider_bridge_config(root.path(), &device_key).unwrap();
        let sealed = fs::read(&note).unwrap();
        let marker_path = root.path().join("identity/localhost-file-key-v1");
        let marker = fs::read(&marker_path).unwrap();
        let mismatch = "identity/localhost-file-key-v1 does not match this Home (restored or copied folder, changed device key). Restore the matching identity/device.key, or move AppCapsules, ElastOS, Local, Users, and UsersAI aside to start empty, then restart.";

        expect_refusal(root.path(), &other_key, mismatch, false);
        assert_eq!(fs::read(&note).unwrap(), sealed);
        assert_eq!(fs::read(&marker_path).unwrap(), marker);

        match localhost_bringup(root.path(), &device_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => panic!("restoring the device key refused: {got}"),
        }
        assert!(elastos_server::local_apps::local_apps_refusal(root.path()).is_none());
        assert_eq!(fs::read(&note).unwrap(), sealed);
        assert_envelope_opens_with_exactly_one_key(&note, b"kept", &device_key, &file_key);
        assert_eq!(fs::read(&marker_path).unwrap(), marker);

        fs::remove_file(&note).unwrap();
        fs::create_dir_all(root.path().join("AppCapsules")).unwrap();
        let lock = root.path().join("identity/localhost-file-key.lock");
        fs::remove_file(&lock).unwrap();
        expect_refusal(root.path(), &other_key, mismatch, false);
        assert_eq!(fs::read(&marker_path).unwrap(), marker);
        assert!(!lock.exists());

        fs::remove_dir_all(root.path().join("Users")).unwrap();
        expect_refusal(root.path(), &other_key, mismatch, false);
        assert_eq!(fs::read(&marker_path).unwrap(), marker);
        assert!(!lock.exists());

        let aside = root.path().with_file_name(format!(
            "{}-aside-AppCapsules",
            root.path().file_name().unwrap().to_string_lossy()
        ));
        fs::rename(root.path().join("AppCapsules"), &aside).unwrap();
        match localhost_bringup(root.path(), &other_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => panic!("empty start refused: {got}"),
        }
        assert!(elastos_server::local_apps::local_apps_refusal(root.path()).is_none());
        assert!(aside.is_dir());
        assert!(!root.path().join("AppCapsules").exists());
        assert!(!note.exists());
        assert_current_marker(root.path(), &other_key);
        fs::remove_dir_all(&aside).unwrap();
    }

    #[test]
    fn plaintext_that_resembles_an_envelope_is_left_alone() {
        let device_key = [0x94; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let look = root.join("Users/look.json");
        let named = root.join("Users/named.json");
        let real = root.join("Users/real.bin");
        fs::create_dir_all(look.parent().unwrap()).unwrap();
        let look_bytes = br#"{"version":1,"nonce":"abcd","ciphertext":"zz"}"#;
        let named_bytes =
            br#"{"nonce":"00112233445566778899aabb","ciphertext":"00112233445566778899aabbccddeeff","version":1}"#;
        fs::write(&look, look_bytes).unwrap();
        fs::write(&named, named_bytes).unwrap();
        plant_device_envelope(&real, &device_key, b"real");
        assert!(localhost_provider::is_encrypted_envelope(named_bytes));
        assert!(!localhost_provider::is_encrypted_envelope(look_bytes));
        let err = localhost_provider_bridge_config(root, &device_key).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Users/named.json"), "{text}");
        assert!(text.contains("not decryptable"), "{text}");
        assert_eq!(fs::read(&look).unwrap(), look_bytes);
        assert_eq!(fs::read(&named).unwrap(), named_bytes);
        assert!(!root.join("identity/localhost-file-key-v1").exists());
        fs::remove_file(&named).unwrap();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(fs::read(&look).unwrap(), look_bytes);
        assert_envelope_opens_with_exactly_one_key(&real, b"real", &device_key, &file_key);
        assert_current_marker(root, &device_key);
    }

    #[test]
    fn an_envelope_in_another_field_order_is_rewritten() {
        let device_key = [0x96; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let path = root.join("Users/reordered.bin");
        let sealed = localhost_provider::encrypt_bytes(&device_key, b"reordered").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        let object = value.as_object().unwrap();
        let mut reordered = serde_json::Map::new();
        reordered.insert("ciphertext".to_string(), object["ciphertext"].clone());
        reordered.insert("nonce".to_string(), object["nonce"].clone());
        reordered.insert("version".to_string(), object["version"].clone());
        let bytes = serde_json::to_vec(&serde_json::Value::Object(reordered)).unwrap();
        assert!(localhost_provider::is_encrypted_envelope(&bytes));
        assert!(
            !bytes.starts_with(br#"{"version":1,"nonce":""#),
            "the row must not use the compact field order"
        );
        assert_eq!(
            localhost_provider::decrypt_bytes(&device_key, &bytes).unwrap(),
            b"reordered"
        );
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &bytes).unwrap();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_ne!(fs::read(&path).unwrap(), bytes);
        assert_envelope_opens_with_exactly_one_key(&path, b"reordered", &device_key, &file_key);
        assert_current_marker(root, &device_key);
    }

    #[test]
    fn a_large_plain_file_is_left_alone_and_an_over_cap_envelope_is_refused() {
        let _guard = LocalAppsGuard::lock();
        let device_key = [0x94; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let plain = root.join("Users/video.bin");
        fs::create_dir_all(plain.parent().unwrap()).unwrap();
        fs::write(&plain, b"ftyp").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&plain)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert!(
            take_localhost_migration_bytes_read() <= 64,
            "the first start read a plain body"
        );
        assert_eq!(take_localhost_migration_opens(), 1);
        let mut head = [0u8; 4];
        std::io::Read::read_exact(&mut std::fs::File::open(&plain).unwrap(), &mut head).unwrap();
        assert_eq!(&head, b"ftyp");
        assert_eq!(fs::metadata(&plain).unwrap().len(), 32 * 1024 * 1024 + 1);
        assert_current_marker(root, &device_key);

        let brace = root.join("Users/brace.bin");
        fs::write(&brace, b"{not-an-envelope").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&brace)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        let over = root.join("Users/over.bin");
        let envelope = localhost_provider::encrypt_bytes(&device_key, b"too-big").unwrap();
        fs::write(&over, &envelope).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&over)
            .unwrap()
            .set_len(32 * 1024 * 1024 + 1)
            .unwrap();
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        let read = take_localhost_migration_bytes_read();
        let opens = take_localhost_migration_opens();
        assert!(
            read > 32 * 1024 * 1024,
            "the new files were not read: {read}"
        );
        assert_eq!(opens, 2, "the settled plain file was opened: {opens}");
        home_is_up(root);
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(take_localhost_migration_bytes_read(), 0);
        assert_eq!(take_localhost_migration_opens(), 0);
        assert_read_refused_by_name(&brace, &file_key, "Users/brace.bin");
        assert_read_refused_by_name(&over, &file_key, "Users/over.bin");
        assert_read_refused_by_name(&plain, &file_key, "Users/video.bin");
        assert_eq!(fs::metadata(&over).unwrap().len(), 32 * 1024 * 1024 + 1);
        let mut prefix = vec![0u8; envelope.len()];
        std::io::Read::read_exact(&mut std::fs::File::open(&over).unwrap(), &mut prefix).unwrap();
        assert_eq!(prefix, envelope);
        let small = root.join("Users/small.bin");
        plant_device_envelope(&small, &device_key, b"small");
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(&small, b"small", &device_key, &file_key);
        assert_eq!(
            localhost_provider::read_sealed_localhost_file(&file_key, &small, "Users/small.bin")
                .unwrap(),
            b"small"
        );
        home_is_up(root);
    }

    #[test]
    fn a_write_failure_names_free_space_or_the_folder() {
        use std::os::unix::fs::PermissionsExt;

        let _clear = ClearLocalhostMigrationFaults;
        let device_key = [0x93; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let full = TempDir::new().unwrap();
        let full_path = full.path().join("Users/full.bin");
        let planted = plant_device_envelope(&full_path, &device_key, b"keep");
        set_localhost_migration_write_error(Some(libc::ENOSPC));
        let err = localhost_provider_bridge_config(full.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("Users/full.bin could not be written"),
            "{text}"
        );
        assert!(text.contains("No space left on device"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        assert_eq!(fs::read(&full_path).unwrap(), planted);
        assert!(!full.path().join("identity/localhost-file-key-v1").exists());
        assert_no_localhost_rewrite_temps(full.path());
        set_localhost_migration_write_error(None);
        localhost_provider_bridge_config(full.path(), &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(&full_path, b"keep", &device_key, &file_key);

        let locked = TempDir::new().unwrap();
        let locked_path = locked.path().join("Users/locked.bin");
        let planted = plant_device_envelope(&locked_path, &device_key, b"stay");
        let users = locked.path().join("Users");
        fs::set_permissions(&users, fs::Permissions::from_mode(0o555)).unwrap();
        struct RestoreMode {
            path: std::path::PathBuf,
        }
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
            }
        }
        let _restore = RestoreMode {
            path: users.clone(),
        };
        let err = localhost_provider_bridge_config(locked.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("Users/locked.bin could not be written"),
            "{text}"
        );
        assert!(text.contains("Permission denied"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        assert_eq!(fs::read(&locked_path).unwrap(), planted);
        assert!(!locked
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());
    }

    #[test]
    fn creating_the_identity_folder_or_the_lock_names_the_write_failure() {
        use std::os::unix::fs::PermissionsExt;

        let device_key = [0xc3; 32];
        let root = TempDir::new().unwrap();
        let note = root.path().join("Users/note.bin");
        let planted = plant_device_envelope(&note, &device_key, b"stay");
        struct RestoreMode {
            path: std::path::PathBuf,
        }
        impl Drop for RestoreMode {
            fn drop(&mut self) {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755));
            }
        }
        let _restore_root = RestoreMode {
            path: root.path().to_path_buf(),
        };
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o555)).unwrap();
        let err = localhost_provider_bridge_config(root.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("identity could not be written"), "{text}");
        assert!(text.contains("Permission denied"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(fs::read(&note).unwrap(), planted);
        assert!(!root.path().join("identity").exists());

        let locked = TempDir::new().unwrap();
        let locked_note = locked.path().join("Users/note.bin");
        let planted = plant_device_envelope(&locked_note, &device_key, b"stay");
        let identity = locked.path().join("identity");
        fs::create_dir(&identity).unwrap();
        let _restore_identity = RestoreMode {
            path: identity.clone(),
        };
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o555)).unwrap();
        let err = localhost_provider_bridge_config(locked.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("identity/localhost-file-key.lock could not be written"),
            "{text}"
        );
        assert!(text.contains("Permission denied"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(fs::read(&locked_note).unwrap(), planted);
        assert!(!locked
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());

        let leftover = TempDir::new().unwrap();
        let users = leftover.path().join("Users");
        fs::create_dir_all(&users).unwrap();
        let temp_name = users.join(".note.bin.elastos-localhost-file-key-v1.tmp");
        fs::write(&temp_name, b"temp").unwrap();
        let note = users.join("note.bin");
        plant_device_envelope(&note, &device_key, b"stay");
        let owned_dir = leftover.path().join("identity/localhost-file-key-v1.tmpd");
        fs::create_dir_all(&owned_dir).unwrap();
        let owned = owned_dir.join("crash.tmp");
        fs::write(&owned, b"crash").unwrap();
        localhost_provider_bridge_config(leftover.path(), &device_key).unwrap();
        assert_eq!(fs::read(&temp_name).unwrap(), b"temp");
        assert!(!owned.exists());
        assert_envelope_opens_with_exactly_one_key(
            &note,
            b"stay",
            &device_key,
            &expected_localhost_file_key(&device_key),
        );

        let _clear = ClearLocalhostMigrationFaults;
        let full_identity = TempDir::new().unwrap();
        let full_note = full_identity.path().join("Users/note.bin");
        let planted = plant_device_envelope(&full_note, &device_key, b"stay");
        set_localhost_migration_create_error(Some(libc::ENOSPC));
        let err = localhost_provider_bridge_config(full_identity.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("identity could not be written"), "{text}");
        assert!(text.contains("No space left on device"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        assert_eq!(fs::read(&full_note).unwrap(), planted);
        assert!(!full_identity.path().join("identity").exists());
        set_localhost_migration_create_error(None);
        localhost_provider_bridge_config(full_identity.path(), &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(
            &full_note,
            b"stay",
            &device_key,
            &expected_localhost_file_key(&device_key),
        );

        let full_lock = TempDir::new().unwrap();
        let lock_note = full_lock.path().join("Users/note.bin");
        let planted = plant_device_envelope(&lock_note, &device_key, b"stay");
        fs::create_dir(full_lock.path().join("identity")).unwrap();
        set_localhost_migration_create_error(Some(libc::ENOSPC));
        let err = localhost_provider_bridge_config(full_lock.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("identity/localhost-file-key.lock could not be written"),
            "{text}"
        );
        assert!(text.contains("No space left on device"), "{text}");
        assert!(
            text.contains("Free space, or the folder's permissions, then restart."),
            "{text}"
        );
        assert!(!text.contains("is not readable"), "{text}");
        assert_eq!(fs::read(&lock_note).unwrap(), planted);
        assert!(!full_lock
            .path()
            .join("identity/localhost-file-key-v1")
            .exists());
        set_localhost_migration_create_error(None);
    }

    #[test]
    fn rewrite_keeps_an_owner_mode_and_drops_extra_attributes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        #[cfg(target_os = "macos")]
        use std::process::Command;

        let device_key = [0x95; 32];
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let owner = root.join("Users/owner.bin");
        let wide = root.join("Users/wide.bin");
        plant_device_envelope(&owner, &device_key, b"owner");
        plant_device_envelope(&wide, &device_key, b"wide");
        #[cfg(target_os = "macos")]
        {
            assert!(Command::new("xattr")
                .args(["-w", "com.elastos.test", "1", owner.to_str().unwrap()])
                .status()
                .unwrap()
                .success());
        }
        fs::set_permissions(&owner, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o644)).unwrap();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        assert_eq!(fs::metadata(&owner).unwrap().mode() & 0o777, 0o400);
        assert_eq!(fs::metadata(&wide).unwrap().mode() & 0o777, 0o600);
        #[cfg(target_os = "macos")]
        {
            assert!(!Command::new("xattr")
                .args(["-p", "com.elastos.test", owner.to_str().unwrap()])
                .status()
                .unwrap()
                .success());
        }
    }

    #[test]
    fn a_plain_file_is_ruled_out_from_its_header() {
        let _clear = ClearLocalhostMigrationFaults;
        let _ = take_localhost_migration_bytes_read();
        let device_key = [0x21; 32];
        let temp = TempDir::new().unwrap();
        let plain = temp.path().join("Users/video.bin");
        fs::create_dir_all(plain.parent().unwrap()).unwrap();
        fs::write(&plain, b"ftyp").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&plain)
            .unwrap()
            .set_len(1024 * 1024)
            .unwrap();
        localhost_provider_bridge_config(temp.path(), &device_key).unwrap();
        let read = take_localhost_migration_bytes_read();
        assert!(read <= 64, "read the plain body: {read}");
        let mut head = [0u8; 4];
        std::io::Read::read_exact(&mut std::fs::File::open(&plain).unwrap(), &mut head).unwrap();
        assert_eq!(&head, b"ftyp");
        assert_eq!(fs::metadata(&plain).unwrap().len(), 1024 * 1024);
    }

    #[test]
    fn a_same_length_rewrite_in_place_is_kept() {
        use std::io::Write;

        let _clear = ClearLocalhostMigrationFaults;
        let device_key = [0x22; 32];
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("Users/note.bin");
        let original = plant_device_envelope(&path, &device_key, b"same-length");
        let flipped_len = original.len();
        set_localhost_migration_before_replace(Some(Box::new(move |path| {
            let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
            let mut flipped = fs::read(path).unwrap();
            assert_eq!(flipped.len(), flipped_len);
            flipped[10] ^= 0xff;
            file.write_all(&flipped).unwrap();
            file.sync_all().unwrap();
        })));
        let err = localhost_provider_bridge_config(temp.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("changed while read"), "{text}");
        let now = fs::read(&path).unwrap();
        assert_eq!(now.len(), original.len());
        assert_ne!(now, original);
        assert!(!temp.path().join("identity/localhost-file-key-v1").exists());
    }

    #[test]
    fn a_marker_temp_from_a_crash_is_removed_on_the_next_walk() {
        let device_key = [0x23; 32];
        let temp = TempDir::new().unwrap();
        let note = temp.path().join("Users/note.bin");
        plant_device_envelope(&note, &device_key, b"kept");
        localhost_provider_bridge_config(temp.path(), &device_key).unwrap();
        let marker = fs::read(temp.path().join("identity/localhost-file-key-v1")).unwrap();
        let stale = temp
            .path()
            .join("identity/.localhost-file-key-v1.elastos-localhost-file-key-v1.tmp");
        fs::write(&stale, b"stale").unwrap();
        let owned_dir = temp.path().join("identity/localhost-file-key-v1.tmpd");
        fs::create_dir_all(&owned_dir).unwrap();
        let owned = owned_dir.join("crash.tmp");
        fs::write(&owned, b"crash").unwrap();
        localhost_provider_bridge_config(temp.path(), &device_key).unwrap();
        assert_eq!(fs::read(&stale).unwrap(), b"stale");
        assert!(!owned.exists());
        assert_eq!(
            fs::read(temp.path().join("identity/localhost-file-key-v1")).unwrap(),
            marker
        );
    }

    #[test]
    fn a_long_file_name_still_migrates() {
        let device_key = [0x24; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let name = "n".repeat(221);
        let path = temp.path().join("Users").join(&name);
        plant_device_envelope(&path, &device_key, b"long-name");
        localhost_provider_bridge_config(temp.path(), &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(&path, b"long-name", &device_key, &file_key);
        assert_current_marker(temp.path(), &device_key);
    }

    #[test]
    fn a_short_marker_fingerprint_is_forged() {
        let device_key = [0x25; 32];
        let temp = TempDir::new().unwrap();
        let note = temp.path().join("Users/note.bin");
        let planted = plant_device_envelope(&note, &device_key, b"stay");
        fs::create_dir_all(temp.path().join("identity")).unwrap();
        fs::write(
            temp.path().join("identity/localhost-file-key-v1"),
            b"elastos-localhost-file-v1 1 aa\n",
        )
        .unwrap();
        let err = localhost_provider_bridge_config(temp.path(), &device_key).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("is not the migration record"), "{text}");
        assert!(
            text.contains("Delete identity/localhost-file-key-v1, then restart."),
            "{text}"
        );
        assert!(!text.contains("does not match"), "{text}");
        assert_eq!(fs::read(&note).unwrap(), planted);
        fs::remove_file(temp.path().join("identity/localhost-file-key-v1")).unwrap();
        localhost_provider_bridge_config(temp.path(), &device_key).unwrap();
        assert_envelope_opens_with_exactly_one_key(
            &note,
            b"stay",
            &device_key,
            &expected_localhost_file_key(&device_key),
        );
    }

    #[test]
    fn an_over_hard_file_is_named_and_moving_it_out_restores_local_apps() {
        let _guard = LocalAppsGuard::lock();
        let device_key = [0x44; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let root = TempDir::new().unwrap();
        let huge = root.path().join("Users/huge.bin");
        fs::create_dir_all(huge.parent().unwrap()).unwrap();
        fs::write(&huge, b"{device-key").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&huge)
            .unwrap()
            .set_len(localhost_provider::SEALED_READ_HARD_LIMIT + 1)
            .unwrap();
        let video = root.path().join("Users/video.bin");
        fs::write(&video, b"ftyp").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&video)
            .unwrap()
            .set_len(localhost_provider::SEALED_READ_HARD_LIMIT + 1)
            .unwrap();
        let small = root.path().join("Users/small.bin");
        plant_device_envelope(&small, &device_key, b"small");
        let sentence = sentence("Users/huge.bin", "larger than this process can read");
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        match localhost_bringup(root.path(), &device_key) {
            LocalhostBringup::Refuse(got) => assert_eq!(got, sentence),
            LocalhostBringup::Start(_) => panic!("an unreadable file started local apps"),
        }
        let line = elastos_server::local_apps::local_apps_health_line(&sentence);
        assert!(line.contains("Users/huge.bin"), "{line}");
        assert!(
            line.contains("Move it out of the folder, then restart."),
            "{line}"
        );
        home_stays_up(root.path(), &sentence);
        assert!(take_localhost_migration_bytes_read() < 1024 * 1024);
        assert_eq!(
            fs::metadata(&huge).unwrap().len(),
            localhost_provider::SEALED_READ_HARD_LIMIT + 1
        );
        let mut video_head = [0u8; 4];
        std::io::Read::read_exact(&mut std::fs::File::open(&video).unwrap(), &mut video_head)
            .unwrap();
        assert_eq!(&video_head, b"ftyp");
        assert_envelope_opens_with_exactly_one_key(&small, b"small", &device_key, &file_key);
        let _ = take_localhost_migration_opens();
        let _ = take_localhost_migration_bytes_read();
        match localhost_bringup(root.path(), &device_key) {
            LocalhostBringup::Refuse(got) => assert_eq!(got, sentence),
            LocalhostBringup::Start(_) => panic!("the named file was forgotten"),
        }
        assert_eq!(take_localhost_migration_opens(), 0);
        assert_eq!(take_localhost_migration_bytes_read(), 0);
        let outside = root.path().join("huge-out.bin");
        fs::rename(&huge, &outside).unwrap();
        match localhost_bringup(root.path(), &device_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => {
                panic!("moving the file out did not restore apps: {got}")
            }
        }
        home_is_up(root.path());
        assert_eq!(
            fs::metadata(&outside).unwrap().len(),
            localhost_provider::SEALED_READ_HARD_LIMIT + 1
        );
        let mut head = [0u8; 1];
        std::io::Read::read_exact(&mut std::fs::File::open(&outside).unwrap(), &mut head).unwrap();
        assert_eq!(&head, b"{");
        assert_eq!(
            localhost_provider::read_sealed_localhost_file(&file_key, &small, "Users/small.bin")
                .unwrap(),
            b"small"
        );
    }

    #[test]
    fn a_file_the_new_key_wrote_over_the_cap_stays_readable() {
        const CHILD: &str = "ELASTOS_LOCALHOST_KEEP_CHILD";
        if std::env::var("ELASTOS_LOCALHOST_MIGRATE_CHILD").as_deref() == Ok("1") {
            let root =
                std::path::PathBuf::from(std::env::var("ELASTOS_LOCALHOST_KEEP_ROOT").unwrap());
            let raw = hex::decode(std::env::var("ELASTOS_LOCALHOST_KEEP_KEY").unwrap()).unwrap();
            let mut device_key = [0u8; 32];
            device_key.copy_from_slice(&raw);
            let file_len: i64 = std::env::var("ELASTOS_LOCALHOST_MIGRATE_LEN")
                .unwrap()
                .parse()
                .unwrap();
            let before = resident_peak();
            match localhost_bringup(&root, &device_key) {
                LocalhostBringup::Start(_) => {}
                LocalhostBringup::Refuse(got) => panic!("migration refused: {got}"),
            }
            let delta = resident_peak().saturating_sub(before);
            eprintln!("SL_R8_MIGRATE_DELTA={delta} FILE={file_len}");
            assert!(
                delta <= file_len * 2 + 8 * 1024 * 1024,
                "the rewrite held more than twice the file: {delta} for {file_len}"
            );
            assert!(
                delta >= file_len / 2,
                "the rewrite did not hold the file: {delta} for {file_len}"
            );
            return;
        }
        if std::env::var(CHILD).as_deref() == Ok("1") {
            let root =
                std::path::PathBuf::from(std::env::var("ELASTOS_LOCALHOST_KEEP_ROOT").unwrap());
            let raw = hex::decode(std::env::var("ELASTOS_LOCALHOST_KEEP_KEY").unwrap()).unwrap();
            let mut device_key = [0u8; 32];
            device_key.copy_from_slice(&raw);
            let before = resident_peak();
            match localhost_bringup(&root, &device_key) {
                LocalhostBringup::Start(_) => {}
                LocalhostBringup::Refuse(got) => {
                    panic!("restart refused a file this key wrote: {got}")
                }
            }
            let after = resident_peak();
            let delta = after.saturating_sub(before);
            eprintln!("SL_R6_KEEP_RSS_BEFORE={before} AFTER={after} DELTA={delta}");
            assert!(
                delta < 64 * 1024 * 1024,
                "the restart read an over-cap envelope: {delta}"
            );
            let file_key = expected_localhost_file_key(&device_key);
            for (name, byte, len) in [
                ("seventeen.bin", 0x5au8, 17 * 1024 * 1024),
                ("hundred.bin", 0x11u8, 100 * 1024 * 1024),
            ] {
                let plain = localhost_provider::read_sealed_localhost_file(
                    &file_key,
                    &root.join("Users").join(name),
                    &format!("Users/{name}"),
                )
                .unwrap_or_else(|err| panic!("{name} was refused on read: {err}"));
                assert_eq!(plain.len(), len, "{name}");
                assert!(plain.iter().all(|item| *item == byte), "{name}");
            }
            return;
        }

        let device_key = [0x26; 32];
        let _guard = LocalAppsGuard::lock();
        let file_key = expected_localhost_file_key(&device_key);
        let migrating = TempDir::new().unwrap();
        let old = migrating.path().join("Users/old.bin");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        let old_plain = vec![0x22u8; 17 * 1024 * 1024];
        let old_bytes = localhost_provider::encrypt_bytes(&device_key, &old_plain).unwrap();
        fs::write(&old, &old_bytes).unwrap();
        assert!(old_bytes.len() as u64 > 32 * 1024 * 1024);
        let small_old = migrating.path().join("Users/small.bin");
        plant_device_envelope(&small_old, &device_key, b"small");
        let test = format!(
            "{}::a_file_the_new_key_wrote_over_the_cap_stays_readable",
            module_path!().split_once("::").unwrap().1
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .env("ELASTOS_LOCALHOST_MIGRATE_CHILD", "1")
            .env("ELASTOS_LOCALHOST_KEEP_ROOT", migrating.path())
            .env("ELASTOS_LOCALHOST_KEEP_KEY", hex::encode(device_key))
            .env("ELASTOS_LOCALHOST_MIGRATE_LEN", old_bytes.len().to_string())
            .args(["--exact", test.as_str(), "--nocapture", "--test-threads=1"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "migrate child failed\nstdout {stdout}\nstderr {stderr}"
        );
        let rss = stderr
            .lines()
            .find(|line| line.contains("SL_R8_MIGRATE_DELTA="))
            .expect("child printed its peak");
        eprintln!("{rss}");
        home_is_up(migrating.path());
        assert_envelope_opens_with_exactly_one_key(&old, &old_plain, &device_key, &file_key);
        assert_eq!(
            localhost_provider::read_sealed_localhost_file(&file_key, &old, "Users/old.bin")
                .unwrap(),
            old_plain
        );
        assert_envelope_opens_with_exactly_one_key(&small_old, b"small", &device_key, &file_key);
        assert_current_marker(migrating.path(), &device_key);
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        match localhost_bringup(migrating.path(), &device_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => panic!("the second start refused: {got}"),
        }
        assert_eq!(
            take_localhost_migration_opens(),
            0,
            "the second start opened a settled file"
        );
        assert_eq!(
            take_localhost_migration_bytes_read(),
            0,
            "the second start read a settled body"
        );
        let later = migrating.path().join("Users/later.bin");
        fs::write(&later, &old_bytes).unwrap();
        let _ = take_localhost_migration_bytes_read();
        let _ = take_localhost_migration_opens();
        match localhost_bringup(migrating.path(), &device_key) {
            LocalhostBringup::Start(_) => {}
            LocalhostBringup::Refuse(got) => {
                panic!("a later over-cap file turned local apps off: {got}")
            }
        }
        assert_eq!(take_localhost_migration_opens(), 1);
        assert_eq!(
            take_localhost_migration_bytes_read(),
            old_bytes.len() as u64
        );
        assert_envelope_opens_with_exactly_one_key(&later, &old_plain, &device_key, &file_key);
        assert_eq!(
            localhost_provider::read_sealed_localhost_file(&file_key, &old, "Users/old.bin")
                .unwrap(),
            old_plain
        );

        let kept = TempDir::new().unwrap();
        plant_device_envelope(&kept.path().join("Users/small.bin"), &device_key, b"small");
        localhost_provider_bridge_config(kept.path(), &device_key).unwrap();
        for (name, byte, len) in [
            ("seventeen.bin", 0x5au8, 17 * 1024 * 1024),
            ("hundred.bin", 0x11u8, 100 * 1024 * 1024),
        ] {
            let plain = vec![byte; len];
            let sealed = localhost_provider::encrypt_file_key_bytes(&file_key, &plain).unwrap();
            assert!(sealed.len() as u64 > 32 * 1024 * 1024, "{name}");
            fs::write(kept.path().join("Users").join(name), &sealed).unwrap();
        }
        let test = format!(
            "{}::a_file_the_new_key_wrote_over_the_cap_stays_readable",
            module_path!().split_once("::").unwrap().1
        );
        let output = Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .env("ELASTOS_LOCALHOST_KEEP_ROOT", kept.path())
            .env("ELASTOS_LOCALHOST_KEEP_KEY", hex::encode(device_key))
            .args(["--exact", test.as_str(), "--nocapture", "--test-threads=1"])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "keep child failed\nstdout {stdout}\nstderr {stderr}"
        );
        let rss = stderr
            .lines()
            .find(|line| line.contains("SL_R6_KEEP_RSS_"))
            .expect("child printed its peak");
        let delta: i64 = rss.split_once("DELTA=").unwrap().1.trim().parse().unwrap();
        assert!(delta < 64 * 1024 * 1024, "{rss}");
        eprintln!("{rss}");
    }

    #[tokio::test]
    async fn home_browser_refusal_is_the_inspect_state() {
        use elastos_server::inspect_provider::InspectSource;
        use std::os::unix::fs::PermissionsExt;

        let _guard = LocalAppsGuard::lock();
        let device_key = [0x27; 32];
        let root = TempDir::new().unwrap();
        let secret = root.path().join("Users/secret.bin");
        plant_device_envelope(&secret, &device_key, b"hidden");
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o000)).unwrap();
        let registry = Arc::new(provider::ProviderRegistry::new());
        register_localhost_without_helper(&registry, root.path(), &device_key).await;
        let sentence = elastos_server::local_apps::local_apps_refusal(root.path())
            .expect("home --browser stored the refusal");
        assert!(sentence.contains("Users/secret.bin"), "{sentence}");
        assert!(sentence.contains(". "), "{sentence}");
        let source = elastos_server::inspect_provider::RegistryInspectSource::new(
            Arc::downgrade(&registry),
            root.path().to_path_buf(),
        );
        let entry = source
            .inspect_get("provider:localhost")
            .await
            .expect("localhost is listed");
        assert_eq!(entry.status, sentence);
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[derive(Clone)]
    struct ProgressWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for ProgressWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn migration_logs_progress_every_few_seconds() {
        const CHILD: &str = "ELASTOS_LOCALHOST_PROGRESS_CHILD";
        let test = format!(
            "{}::migration_logs_progress_every_few_seconds",
            module_path!().split_once("::").unwrap().1
        );
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let output = Command::new(std::env::current_exe().unwrap())
                .env(CHILD, "1")
                .args(["--exact", test.as_str(), "--nocapture", "--test-threads=1"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "progress child failed\nstdout {stdout}\nstderr {stderr}"
            );
            assert!(
                stderr.contains("localhost file migration checked 2 files"),
                "{stderr}"
            );
            assert!(stderr.contains("PROGRESS_EVENTS=1"), "{stderr}");
            let walk_ms = stderr
                .lines()
                .find_map(|line| line.strip_prefix("PROGRESS_WALK_MS="))
                .unwrap_or("missing");
            let walk_ms: u128 = walk_ms.parse().unwrap_or(u128::MAX);
            assert!(walk_ms < 2_000, "the progress row slept: {walk_ms} ms");
            return;
        }
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = ProgressWriter(captured.clone());
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::INFO)
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        )
        .expect("fresh process has no tracing subscriber");
        tracing::callsite::rebuild_interest_cache();
        let device_key = [0x96; 32];
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        plant_device_envelope(&root.join("Users/a.bin"), &device_key, b"a");
        plant_device_envelope(&root.join("Users/b.bin"), &device_key, b"b");
        let _clear = ClearLocalhostMigrationFaults;
        set_localhost_migration_progress_clock(Some(1_000));
        let advanced = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = advanced.clone();
        set_localhost_migration_before_replace(Some(Box::new(move |_| {
            if flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            set_localhost_migration_progress_clock(Some(1_003));
        })));
        let started = Instant::now();
        localhost_provider_bridge_config(root, &device_key).unwrap();
        let walk_ms = started.elapsed().as_millis();
        let text = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        let events = text
            .matches("localhost file migration checked 2 files")
            .count();
        assert_eq!(events, 1, "{text}");
        eprintln!("{text}");
        eprintln!("PROGRESS_EVENTS={events}");
        eprintln!("PROGRESS_WALK_MS={walk_ms}");
    }

    fn spawn_kill_child(root: &std::path::Path, device_key: &[u8; 32], point: &str) -> Child {
        let test = format!(
            "{}::localhost_migration_kill_child",
            module_path!().split_once("::").unwrap().1
        );
        Command::new(std::env::current_exe().unwrap())
            .env("ELASTOS_LOCALHOST_MIGRATION_CHILD_ROOT", root)
            .env(
                "ELASTOS_LOCALHOST_MIGRATION_CHILD_KEY",
                hex::encode(device_key),
            )
            .env("ELASTOS_LOCALHOST_MIGRATION_KILL_AT", point)
            .args([
                "--exact",
                test.as_str(),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    #[ignore]
    fn localhost_migration_kill_child() {
        let Ok(root) = std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_ROOT") else {
            return;
        };
        let bytes =
            hex::decode(std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_KEY").unwrap()).unwrap();
        let mut device_key = [0u8; 32];
        device_key.copy_from_slice(&bytes);
        let _ = localhost_provider_bridge_config(std::path::Path::new(&root), &device_key);
    }

    fn kill_migration_at(point: &str) {
        use std::os::unix::process::ExitStatusExt;

        let device_key = [0x97; 32];
        let file_key = expected_localhost_file_key(&device_key);
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let note = root.join("Users/note.bin");
        let original = plant_device_envelope(&note, &device_key, b"kill-secret");
        let mut child = ReapChild(Some(spawn_kill_child(root, &device_key, point)));
        let probe = root.join("kill-probe");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !probe.exists() {
            assert!(Instant::now() < deadline, "did not reach {point}");
            if let Some(status) = child.child().try_wait().unwrap() {
                panic!("child exited before {point}: {status}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(fs::read(&probe).unwrap(), point.as_bytes());
        child.child().kill().unwrap();
        let status = child.child().wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let temp_dir = root.join("identity/localhost-file-key-v1.tmpd");
        if point == "temp-created" {
            assert_eq!(fs::read(&note).unwrap(), original);
            assert_eq!(fs::read_dir(&temp_dir).unwrap().count(), 1);
            assert!(!root.join("identity/localhost-file-key-v1").exists());
            localhost_provider_bridge_config(root, &device_key).unwrap();
            assert_eq!(fs::read_dir(&temp_dir).unwrap().count(), 0);
            assert_envelope_opens_with_exactly_one_key(
                &note,
                b"kill-secret",
                &device_key,
                &file_key,
            );
            assert_current_marker(root, &device_key);
        } else {
            assert_eq!(
                fs::read_dir(&temp_dir).map(|dir| dir.count()).unwrap_or(0),
                0
            );
            assert!(!root.join("identity/localhost-file-key-v1").exists());
            let rewritten = fs::read(&note).unwrap();
            assert_eq!(
                localhost_provider::decrypt_bytes(&file_key, &rewritten).unwrap(),
                b"kill-secret"
            );
            localhost_provider_bridge_config(root, &device_key).unwrap();
            assert_eq!(fs::read(&note).unwrap(), rewritten);
            assert_current_marker(root, &device_key);
        }
    }

    #[test]
    fn sigkill_during_replace_restarts_clean() {
        kill_migration_at("temp-created");
        kill_migration_at("renamed");
    }

    #[test]
    #[ignore]
    fn localhost_migration_measure_many_files_and_one_large_file() {
        if std::env::var("ELASTOS_LOCALHOST_MIGRATION_MEASURE")
            .ok()
            .as_deref()
            != Some("1")
        {
            return;
        }
        let device_key = [0x98; 32];
        let many = TempDir::new().unwrap();
        let dir = many.path().join("Users/bulk");
        fs::create_dir_all(&dir).unwrap();
        for n in 0..20_000 {
            fs::write(dir.join(format!("{n:05}")), b"x").unwrap();
        }
        eprintln!("SL_R5_LOAD_START={}", load_average());
        let started = Instant::now();
        localhost_provider_bridge_config(many.path(), &device_key).unwrap();
        eprintln!("SL_R5_20K_MS={}", started.elapsed().as_millis());

        let large = TempDir::new().unwrap();
        let big = large.path().join("Users/huge.bin");
        fs::create_dir_all(big.parent().unwrap()).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&big)
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        let before = resident_peak();
        let started = Instant::now();
        localhost_provider_bridge_config(large.path(), &device_key).unwrap();
        let after = resident_peak();
        eprintln!(
            "SL_R5_1GB_MS={} RSS_BEFORE={} RSS_AFTER={} LOAD={}",
            started.elapsed().as_millis(),
            before,
            after,
            load_average()
        );
        assert_eq!(fs::metadata(&big).unwrap().len(), 1 << 30);
        let mut head = [0u8; 4];
        std::io::Read::read_exact(&mut std::fs::File::open(&big).unwrap(), &mut head).unwrap();
        assert_eq!(head, [0, 0, 0, 0]);
        let delta = after.saturating_sub(before);
        assert!(delta < 256 * 1024 * 1024, "held the large file: {delta}");
    }

    fn load_average() -> String {
        let mut load = [0f64; 3];
        let count = unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        if count < 3 {
            return "unavailable".to_string();
        }
        format!("{:.2} {:.2} {:.2}", load[0], load[1], load[2])
    }

    fn ru_maxrss_to_bytes(raw: i64, linux_kib: bool) -> i64 {
        if linux_kib {
            raw.saturating_mul(1024)
        } else {
            raw
        }
    }

    fn resident_peak() -> i64 {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return 0;
        }
        ru_maxrss_to_bytes(usage.ru_maxrss, cfg!(target_os = "linux"))
    }

    #[test]
    fn peak_memory_converts_linux_ru_maxrss_from_kib() {
        assert_eq!(ru_maxrss_to_bytes(256 * 1024, true), 256 * 1024 * 1024);
        assert_eq!(ru_maxrss_to_bytes(17_000_000, false), 17_000_000);
        let held = ru_maxrss_to_bytes((200 * 1024 * 1024) / 1024, true);
        assert!(
            held >= 200 * 1024 * 1024,
            "Linux ru_maxrss is kibibytes: {held}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn chain_provider_bridge_config_uses_derived_issuer_and_private_network() {
        let tempdir = TempDir::new().unwrap();
        let network = write_protected_content_chain_config(&tempdir);
        let device_key = [0x5a; 32];
        let issuer = derive_protected_content_runtime_issuer(&device_key).unwrap();
        let (expected_signing_key, _) = elastos_identity::derive_did(&device_key);

        let config = chain_provider_bridge_config(tempdir.path(), &issuer).unwrap();

        assert_eq!(
            issuer.as_bytes(),
            &expected_signing_key.verifying_key().to_bytes()
        );
        assert_eq!(
            config.extra["protected_content_runtime_issuer"],
            format!("0x{}", hex::encode(issuer.as_bytes()))
        );
        let signing_seed = expected_signing_key.to_bytes();
        assert_ne!(signing_seed.as_slice(), device_key.as_slice());
        assert_ne!(signing_seed.as_slice(), issuer.as_bytes().as_slice());
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(
            !serialized.contains(&hex::encode(device_key)),
            "chain config contains the device private key"
        );
        assert!(
            !serialized.contains(&hex::encode(signing_seed)),
            "chain config contains the device signing seed"
        );
        assert!(serialized.contains(&hex::encode(issuer.as_bytes())));
        assert!(config.encryption_key.is_empty());
        assert_eq!(config.extra["protected_content_network"], network);
        let private_file =
            fs::read_to_string(tempdir.path().join("protected-content/chain-provider.json"))
                .unwrap();
        assert!(!private_file.contains("protected_content_runtime_issuer"));
        assert!(!private_file.contains(&hex::encode(issuer.as_bytes())));
    }

    #[test]
    fn chain_provider_bridge_config_accepts_missing_private_network() {
        let tempdir = TempDir::new().unwrap();
        let issuer = derive_protected_content_runtime_issuer(&[0x5b; 32]).unwrap();

        let config = chain_provider_bridge_config(tempdir.path(), &issuer).unwrap();

        assert!(config.extra.get("protected_content_network").is_none());
        assert_eq!(
            config.extra["protected_content_runtime_issuer"],
            format!("0x{}", hex::encode(issuer.as_bytes()))
        );
        assert!(!tempdir.path().join("protected-content").exists());
    }

    #[cfg(unix)]
    #[test]
    fn invalid_private_chain_config_keeps_only_generic_chain_init_and_redacts_values() {
        let tempdir = TempDir::new().unwrap();
        let network = write_protected_content_chain_config(&tempdir);
        let path = tempdir.path().join("protected-content/chain-provider.json");
        let mut invalid: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        invalid["unexpected"] = serde_json::json!("private-secret.example.invalid");
        fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let issuer = derive_protected_content_runtime_issuer(&[0x5c; 32]).unwrap();

        let error = chain_provider_bridge_config(tempdir.path(), &issuer).unwrap_err();
        let protected = chain_provider_protected_startup_config(tempdir.path(), &issuer);
        let generic = chain_provider_bridge_config_without_protected_network(&issuer);

        assert!(!error.to_string().contains("private-secret.example.invalid"));
        assert!(!error
            .to_string()
            .contains(network["rpc_url"].as_str().unwrap()));
        assert!(protected.is_none());
        assert!(generic.extra.get("protected_content_network").is_none());
        assert!(generic.extra.get("networks").is_none());
        assert_eq!(
            generic.extra["protected_content_runtime_issuer"],
            format!("0x{}", hex::encode(issuer.as_bytes()))
        );
    }

    #[test]
    fn model_provider_bridge_config_keeps_unvalidated_offers_without_credentials() {
        let tempdir = TempDir::new().unwrap();
        let raw = serde_json::json!({
            "offers": [
                {
                    "id": "offer:flash-chat:pair-a",
                    "title": "Flash chat",
                    "operation": "text.generate",
                    "input_modalities": ["text/plain"],
                    "output_modalities": ["text/plain"],
                    "policy": {
                        "concurrency_limit": 1,
                        "input_bytes_limit": 1024,
                        "inline_output_bytes_limit": 2048,
                        "event_bytes_limit": 4096,
                        "runtime_ms_limit": 1000,
                        "retention_secs": 60,
                        "cancel_settlement_timeout_ms": 1000
                    },
                    "adapter": {
                        "kind": "open_ai_compatible_text",
                        "api_url": "https://example.invalid/v1/chat/completions",
                        "api_key": "Bearer super-secret",
                        "model": "pair-a"
                    }
                },
                {
                    "id": "offer:nested-invalid",
                    "title": "Broken nested config",
                    "operation": "text.generate",
                    "input_modalities": ["text/plain"],
                    "output_modalities": ["text/plain"],
                    "policy": {
                        "concurrency_limit": 1,
                        "input_bytes_limit": 1024,
                        "inline_output_bytes_limit": 2048,
                        "event_bytes_limit": 4096,
                        "runtime_ms_limit": 1000,
                        "retention_secs": 60,
                        "cancel_settlement_timeout_ms": 1000
                    },
                    "adapter": {
                        "kind": "open_ai_compatible_text"
                    }
                }
            ]
        });
        write_model_provider_operator_config(&tempdir, &raw.to_string());

        let config = model_provider_bridge_config(tempdir.path()).unwrap();

        let mut expected = raw["offers"].clone();
        expected[0]["adapter"]
            .as_object_mut()
            .unwrap()
            .remove("api_key");
        assert_eq!(config.extra["offers"], expected);
        assert!(!config.extra.to_string().contains("super-secret"));
    }

    #[test]
    fn model_provider_bridge_config_rejects_invalid_top_level_shape_without_echoing_secrets() {
        let tempdir = TempDir::new().unwrap();
        let cases = [
            r#"{"offers":[],"extra":"nope"}"#,
            r#"{"offers":[],"offers":[]}"#,
            r#"{"offers":{"id":"not-an-array"}}"#,
            r#"["not-an-object"]"#,
        ];
        for raw in cases {
            write_model_provider_operator_config(&tempdir, raw);
            let error = model_provider_bridge_config(tempdir.path()).unwrap_err();
            assert!(!error.to_string().contains("super-secret"));
            fs::remove_file(model_provider_config_path(tempdir.path())).unwrap();
        }
        write_model_provider_operator_config(
            &tempdir,
            r#"{"offers":[],"authorization":"Bearer super-secret"}"#,
        );
        let error = model_provider_bridge_config(tempdir.path()).unwrap_err();
        assert!(!error.to_string().contains("Bearer super-secret"));
    }

    #[test]
    fn model_provider_bridge_config_has_no_env_fallback_and_is_read_only() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ELASTOS_MODEL_PROVIDER_CONFIG",
            "ELASTOS_MODEL_PROVIDER_CONFIG_PATH",
        ]);
        std::env::set_var(
            "ELASTOS_MODEL_PROVIDER_CONFIG",
            r#"{"offers":[{"id":"offer:env"}]}"#,
        );
        std::env::set_var("ELASTOS_MODEL_PROVIDER_CONFIG_PATH", "/tmp/not-used.json");
        let tempdir = TempDir::new().unwrap();

        let config = model_provider_bridge_config(tempdir.path()).unwrap();

        assert_eq!(config.extra["offers"], serde_json::json!([]));
        assert!(!model_provider_config_path(tempdir.path()).exists());
    }

    #[test]
    fn model_provider_bridge_config_repeated_reads_leave_operator_config_unchanged() {
        let tempdir = TempDir::new().unwrap();
        let path = write_model_provider_operator_config(&tempdir, r#"{"offers":[]}"#);
        let original_bytes = fs::read(&path).unwrap();
        let original_metadata = fs::metadata(&path).unwrap();

        let first = model_provider_bridge_config(tempdir.path()).unwrap();
        let second = model_provider_bridge_config(tempdir.path()).unwrap();

        assert_eq!(first.extra["offers"], serde_json::json!([]));
        assert_eq!(second.extra["offers"], serde_json::json!([]));
        assert_eq!(fs::read(&path).unwrap(), original_bytes);
        let final_metadata = fs::metadata(&path).unwrap();
        assert_eq!(final_metadata.len(), original_metadata.len());
        #[cfg(unix)]
        assert_eq!(
            final_metadata.permissions().mode() & 0o777,
            original_metadata.permissions().mode() & 0o777
        );
    }

    #[test]
    fn model_provider_bridge_config_rejects_oversized_operator_config() {
        let tempdir = TempDir::new().unwrap();
        let oversized = format!(
            "{{\"offers\":[],\"padding\":\"{}\"}}",
            "x".repeat(MODEL_PROVIDER_CONFIG_MAX_BYTES)
        );
        write_model_provider_operator_config(&tempdir, &oversized);

        let error = model_provider_bridge_config(tempdir.path()).unwrap_err();

        assert!(error.to_string().contains("byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn model_provider_bridge_config_rejects_insecure_or_nonregular_operator_config() {
        use std::os::unix::fs::symlink;

        let tempdir = TempDir::new().unwrap();
        let path = write_model_provider_operator_config(&tempdir, r#"{"offers":[]}"#);

        fs::set_permissions(
            tempdir.path().join("providers"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(model_provider_bridge_config(tempdir.path()).is_err());
        fs::set_permissions(
            tempdir.path().join("providers"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        fs::set_permissions(
            model_provider_root_dir(tempdir.path()),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(model_provider_bridge_config(tempdir.path()).is_err());
        fs::set_permissions(
            model_provider_root_dir(tempdir.path()),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(model_provider_bridge_config(tempdir.path()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::remove_file(&path).unwrap();
        symlink(tempdir.path().join("missing.json"), &path).unwrap();
        assert!(model_provider_bridge_config(tempdir.path()).is_err());
    }

    #[test]
    fn setup_source_home_does_not_seed_model_provider_operator_config() {
        let script = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../..")
                .join("scripts")
                .join("setup-source-home.sh"),
        )
        .unwrap();

        assert!(!script.contains("providers/model-provider/config.json"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nested_model_provider_config_reaches_spawn_and_provider_exits_without_registration() {
        let tempdir = TempDir::new().unwrap();
        write_model_provider_operator_config(
            &tempdir,
            &serde_json::json!({
                "offers": [{
                    "id": "offer:nested-invalid",
                    "title": "Broken",
                    "operation": "text.generate",
                    "input_modalities": ["text/plain"],
                    "output_modalities": ["text/plain"],
                    "policy": {
                        "concurrency_limit": 1,
                        "input_bytes_limit": 1024,
                        "inline_output_bytes_limit": 2048,
                        "event_bytes_limit": 4096,
                        "runtime_ms_limit": 1000,
                        "retention_secs": 60,
                        "cancel_settlement_timeout_ms": 1000
                    },
                    "adapter": {
                        "kind": "open_ai_compatible_text"
                    }
                }]
            })
            .to_string(),
        );
        let script_path = tempdir.path().join("fake-model-provider.sh");
        let pid_path = tempdir.path().join("fake-model-provider.pid");
        crate::test_support::write_from_child(
            &script_path,
            format!(
                "#!/bin/sh\nprintf '%s' $$ > '{}'\nIFS= read -r _line || exit 0\nprintf '{{\"status\":\"error\",\"code\":\"invalid_config\",\"message\":\"invalid configuration\"}}\\n'\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n",
                pid_path.display()
            ),
            0o700,
        );

        let error = match provider::ProviderBridge::spawn(
            &crate::test_support::fixture_executable(&script_path),
            model_provider_bridge_config(tempdir.path()).unwrap(),
        )
        .await
        {
            Ok(_) => panic!("nested invalid config should not initialize a provider bridge"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("invalid configuration"));
        let pid = fs::read_to_string(&pid_path)
            .unwrap()
            .trim()
            .parse::<libc::pid_t>()
            .unwrap();
        assert_pid_absent(pid);
    }

    struct EnvGuard {
        keys: &'static [&'static str],
    }

    impl EnvGuard {
        fn new(keys: &'static [&'static str]) -> Self {
            for key in keys {
                std::env::remove_var(key);
            }
            Self { keys }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for key in self.keys {
                std::env::remove_var(key);
            }
        }
    }

    #[test]
    fn availability_provider_config_uses_explicit_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ELASTOS_AVAILABILITY_PROVIDER_CONFIG",
            "ELASTOS_AVAILABILITY_ENSURE_URL",
        ]);
        std::env::set_var(
            "ELASTOS_AVAILABILITY_PROVIDER_CONFIG",
            r#"{"targets":[{"id":"test","ensure_url":"https://example.invalid/ensure"}]}"#,
        );

        let config = availability_provider_config_from_env().unwrap();
        assert_eq!(config["targets"][0]["id"], "test");
    }

    #[test]
    fn availability_provider_config_uses_env_endpoint() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ELASTOS_AVAILABILITY_PROVIDER_CONFIG",
            "ELASTOS_AVAILABILITY_ENSURE_URL",
            "ELASTOS_AVAILABILITY_PROVIDER_ID",
            "ELASTOS_AVAILABILITY_AUTHORIZATION",
        ]);
        std::env::set_var(
            "ELASTOS_AVAILABILITY_ENSURE_URL",
            "https://example.invalid/ensure",
        );
        std::env::set_var("ELASTOS_AVAILABILITY_PROVIDER_ID", "elacity");
        std::env::set_var("ELASTOS_AVAILABILITY_AUTHORIZATION", "Bearer secret");

        let config = availability_provider_config_from_env().unwrap();
        assert_eq!(config["targets"][0]["id"], "elacity");
        assert_eq!(
            config["targets"][0]["ensure_url"],
            "https://example.invalid/ensure"
        );
        assert_eq!(config["targets"][0]["authorization"], "Bearer secret");
    }

    #[test]
    fn carrier_peer_attestation_exchange_config_uses_explicit_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_CONFIG",
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_URL",
        ]);
        std::env::set_var(
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_CONFIG",
            r#"{"url":"https://attest.example.invalid/exchange","authorization":"Bearer attest","timeout_secs":8}"#,
        );

        let config = carrier_peer_attestation_exchange_config_from_env().unwrap();
        assert_eq!(config["url"], "https://attest.example.invalid/exchange");
        assert_eq!(config["authorization"], "Bearer attest");
        assert_eq!(config["timeout_secs"], 8);
    }

    #[test]
    fn carrier_peer_attestation_exchange_config_uses_env_endpoint() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_CONFIG",
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_URL",
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_AUTHORIZATION",
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_TIMEOUT_SECS",
        ]);
        std::env::set_var(
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_URL",
            "http://127.0.0.1:9799/peer-attestation/exchange",
        );
        std::env::set_var(
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_AUTHORIZATION",
            "Bearer local-attest",
        );
        std::env::set_var(
            "ELASTOS_CARRIER_PEER_ATTESTATION_EXCHANGE_TIMEOUT_SECS",
            "10",
        );

        let config = carrier_peer_attestation_exchange_config_from_env().unwrap();
        assert_eq!(
            config["url"],
            "http://127.0.0.1:9799/peer-attestation/exchange"
        );
        assert_eq!(config["authorization"], "Bearer local-attest");
        assert_eq!(config["timeout_secs"], 10);
    }

    #[test]
    fn content_repair_scheduler_is_opt_in() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            CONTENT_REPAIR_SCHEDULER_ENV,
            CONTENT_REPAIR_SCHEDULER_INTERVAL_ENV,
            CONTENT_REPAIR_SCHEDULER_LIMIT_ENV,
            CONTENT_REPAIR_SCHEDULER_MAX_ATTEMPTS_ENV,
            CONTENT_REPAIR_SCHEDULER_FAILURE_BUDGET_ENV,
            CONTENT_REPAIR_SCHEDULER_INCLUDE_HEALTHY_ENV,
        ]);

        assert!(content_repair_scheduler_config_from_env().is_none());
    }

    #[test]
    fn content_repair_scheduler_config_clamps_operator_env() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&[
            CONTENT_REPAIR_SCHEDULER_ENV,
            CONTENT_REPAIR_SCHEDULER_INTERVAL_ENV,
            CONTENT_REPAIR_SCHEDULER_LIMIT_ENV,
            CONTENT_REPAIR_SCHEDULER_MAX_ATTEMPTS_ENV,
            CONTENT_REPAIR_SCHEDULER_FAILURE_BUDGET_ENV,
            CONTENT_REPAIR_SCHEDULER_INCLUDE_HEALTHY_ENV,
        ]);
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_ENV, "true");
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_INTERVAL_ENV, "5");
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_LIMIT_ENV, "1000");
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_MAX_ATTEMPTS_ENV, "999");
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_FAILURE_BUDGET_ENV, "999");
        std::env::set_var(CONTENT_REPAIR_SCHEDULER_INCLUDE_HEALTHY_ENV, "yes");

        let config = content_repair_scheduler_config_from_env().unwrap();
        assert_eq!(
            config.interval_secs,
            CONTENT_REPAIR_SCHEDULER_MIN_INTERVAL_SECS
        );
        assert_eq!(config.limit, 100);
        assert_eq!(config.max_attempts, 25);
        assert_eq!(config.failure_budget, 100);
        assert!(config.include_healthy_check);
    }

    #[test]
    fn exit_provider_config_prefers_explicit_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&["ELASTOS_EXIT_PROVIDER_CONFIG"]);
        std::env::set_var(
            "ELASTOS_EXIT_PROVIDER_CONFIG",
            r#"{"backends":[{"id":"local","kind":"http_fetch","allowed_hosts":["example.com"]}]}"#,
        );

        let data_dir = crate::sources::default_data_dir();
        let config = exit_provider_config_from_env(&data_dir).unwrap();
        assert_eq!(config["backends"][0]["id"], "local");
        assert_eq!(config["backends"][0]["kind"], "http_fetch");
    }

    #[test]
    fn browser_engine_adapter_config_prefers_explicit_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&["ELASTOS_BROWSER_ENGINE_ADAPTER_CONFIG"]);
        std::env::set_var(
            "ELASTOS_BROWSER_ENGINE_ADAPTER_CONFIG",
            r#"{"adapters":[{"id":"linux-proof","kind":"contract_proof","display_modes":["webrtc_remote_display"]}]}"#,
        );

        let data_dir = crate::sources::default_data_dir();
        let config = browser_engine_adapter_config_from_env(&data_dir).unwrap();
        assert_eq!(config["adapters"][0]["id"], "linux-proof");
        assert_eq!(config["adapters"][0]["kind"], "contract_proof");
        assert_eq!(
            config["adapters"][0]["display_modes"][0],
            "webrtc_remote_display"
        );
    }

    #[test]
    fn browser_local_exit_config_prefers_explicit_json() {
        let _lock = ENV_LOCK.lock().unwrap();
        let _guard = EnvGuard::new(&["ELASTOS_BROWSER_LOCAL_EXIT_CONFIG"]);
        std::env::set_var(
            "ELASTOS_BROWSER_LOCAL_EXIT_CONFIG",
            r#"{"schema":"elastos.browser.local-exit.config/v1","relay_ipc_path":"/tmp/elastos-browser-local-exit.sock","allowed_hosts":["*"],"replace_existing_socket":true}"#,
        );

        let data_dir = crate::sources::default_data_dir();
        let config = browser_local_exit_config_from_env(&data_dir).unwrap();
        assert_eq!(config["schema"], "elastos.browser.local-exit.config/v1");
        assert_eq!(config["allowed_hosts"][0], "*");
    }

    #[test]
    fn browser_local_exit_relay_path_rejects_relative_and_whitespace_paths() {
        let relative = serde_json::json!({
            "relay_ipc_path": "relative.sock"
        });
        assert!(browser_local_exit_relay_path(&relative).is_err());

        let whitespace = serde_json::json!({
            "relay_ipc_path": "/tmp/elastos browser.sock"
        });
        assert!(browser_local_exit_relay_path(&whitespace).is_err());
    }

    #[test]
    fn browser_local_exit_replace_existing_socket_refuses_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let relay_path = dir.path().join("relay.sock");
        std::fs::write(&relay_path, b"not a socket").unwrap();

        let err = remove_existing_browser_local_exit_socket(&relay_path).unwrap_err();
        assert!(
            err.to_string().contains("not a Unix socket")
                || err
                    .to_string()
                    .contains("replace_existing_socket is only supported")
        );
        assert!(relay_path.exists());
    }

    /// Bindable socket paths must stay under `SUN_LEN`, which `tempfile::tempdir`
    /// paths can overrun on macOS.
    #[cfg(unix)]
    fn bindable_relay_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ele-srv-{}-{tag}.sock", std::process::id()))
    }

    #[cfg(unix)]
    #[test]
    fn browser_local_exit_replace_existing_socket_removes_a_socket_with_no_listener() {
        let relay_path = bindable_relay_path("stale");
        let _ = std::fs::remove_file(&relay_path);
        let listener = std::os::unix::net::UnixListener::bind(&relay_path).unwrap();
        // Rust does not unlink the path on drop, so this leaves the exact shape a
        // hard-killed helper leaves behind: a socket file with nothing serving it.
        drop(listener);
        assert!(relay_path.exists());

        remove_existing_browser_local_exit_socket(&relay_path).unwrap();
        assert!(!relay_path.exists(), "stale relay socket must be reclaimed");
    }

    #[cfg(unix)]
    #[test]
    fn browser_local_exit_replace_existing_socket_refuses_a_live_listener() {
        let relay_path = bindable_relay_path("live");
        let _ = std::fs::remove_file(&relay_path);
        let listener = std::os::unix::net::UnixListener::bind(&relay_path).unwrap();

        // Silently unlinking here is what stranded helpers one per launch: the
        // incumbent keeps serving an unlinked socket that nothing can reach again.
        let err = remove_existing_browser_local_exit_socket(&relay_path).unwrap_err();
        assert!(
            err.to_string().contains("still served by a live helper"),
            "unexpected error: {err}"
        );
        assert!(relay_path.exists(), "a live helper's socket must survive");

        drop(listener);
        let _ = std::fs::remove_file(&relay_path);
    }

    #[test]
    fn browser_local_exit_socket_ready_requires_socket() {
        let dir = tempfile::tempdir().unwrap();
        let relay_path = dir.path().join("relay.sock");
        assert!(!browser_local_exit_socket_ready(&relay_path).unwrap());
        std::fs::write(&relay_path, b"not a socket").unwrap();
        #[cfg(unix)]
        {
            let err = browser_local_exit_socket_ready(&relay_path).unwrap_err();
            assert!(err.to_string().contains("not a Unix socket"), "{err}");
        }
        #[cfg(not(unix))]
        {
            let err = browser_local_exit_socket_ready(&relay_path).unwrap_err();
            assert_eq!(
                err.downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::Unsupported)
            );
            assert!(
                err.to_string().contains("unsupported on this platform"),
                "{err}"
            );
        }
    }

    #[tokio::test]
    async fn carrier_runtime_service_shutdown_releases_endpoint_for_restart() {
        let dir = tempfile::tempdir().unwrap();
        let device_key = elastos_identity::load_or_create_device_key(dir.path()).unwrap();
        let (signing_key, did) = elastos_identity::derive_did(&device_key);

        let node = elastos_server::carrier::start_carrier_node_with_registry(
            &signing_key,
            &did,
            dir.path().to_path_buf(),
            None,
        )
        .await
        .unwrap();
        assert!(
            !node.endpoint.bound_sockets().is_empty(),
            "carrier endpoint should be bound before readiness is published"
        );

        let mut service = elastos_server::carrier::CarrierRuntimeService::new(node);
        service.shutdown().await.unwrap();

        let restarted = elastos_server::carrier::start_carrier_node_with_registry(
            &signing_key,
            &did,
            dir.path().to_path_buf(),
            None,
        )
        .await
        .unwrap();
        let mut restarted_service = elastos_server::carrier::CarrierRuntimeService::new(restarted);
        restarted_service.shutdown().await.unwrap();
    }

    // ---------------------------------------------------------------------
    // `elastos run <native-provider>` standalone provider host.
    //
    // These exercise the real composition: a real custody-provider process on
    // the Runtime-only `custody` target, the in-process content plane that
    // serves a Carrier replica `import_exact`, and a real Carrier node, with
    // no HTTP or TLS surface anywhere.
    // ---------------------------------------------------------------------

    #[cfg(unix)]
    const PROVIDER_HOST_TEST_CUSTODY_BIN_ENV: &str = "ELASTOS_TEST_CUSTODY_PROVIDER_BIN";

    /// A CID the mock ipfs-provider returns for every add, so the content
    /// plane's exact import check sees a matching import.
    #[cfg(unix)]
    const PROVIDER_HOST_TEST_CID: &str =
        "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";

    #[cfg(unix)]
    fn required_provider_host_test_binary(env_name: &str) -> PathBuf {
        let path = PathBuf::from(
            std::env::var_os(env_name)
                .unwrap_or_else(|| panic!("missing test binary env: {env_name}")),
        );
        assert!(
            path.is_file(),
            "test binary is not a file: {}",
            path.display()
        );
        path
    }

    #[cfg(unix)]
    fn owner_only_test_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// A data dir shaped exactly like `elastos protected-content-config
    /// provision-custody-node` leaves it: owner-only, with a provisioned
    /// inactive custody state root bound to this home's Runtime issuer.
    #[cfg(unix)]
    fn provisioned_provider_host_data_dir(temp: &TempDir) -> PathBuf {
        let data_dir = fs::canonicalize(temp.path()).unwrap().join("data");
        owner_only_test_dir(&data_dir);
        let state_root = data_dir.join("protected-content/custody-provider/inactive");
        owner_only_test_dir(state_root.parent().unwrap());
        let device_key = elastos_identity::load_or_create_device_key(&data_dir).unwrap();
        let issuer = derive_protected_content_runtime_issuer(&device_key).unwrap();
        custody_provider::provision_state_root(&state_root, issuer).unwrap();
        data_dir
    }

    /// Install `source` as this Home's `custody-provider` under a signed
    /// release, as `elastos setup` would.
    #[cfg(unix)]
    fn install_signed_custody_provider(data_dir: &Path, source: &Path) -> PathBuf {
        install_signed_providers(data_dir, &[("custody-provider", source)]).remove(0)
    }

    /// Install each `(name, source)` as this Home's native provider under one
    /// signed release, as `elastos setup` would. Every native provider start
    /// admits its executable against the served Home's signed release.
    #[cfg(unix)]
    fn install_signed_providers(data_dir: &Path, providers: &[(&str, &Path)]) -> Vec<PathBuf> {
        use sha2::{Digest as _, Sha256};
        let bin_dir = data_dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let mut external = serde_json::Map::new();
        let mut installed = Vec::new();
        for (name, source) in providers {
            let binary = bin_dir.join(name);
            let bytes = fs::read(source).unwrap();
            crate::test_support::write_from_child(&binary, &bytes, 0o700);
            let provider_runtime = match *name {
                "custody-provider" => serde_json::json!({
                    "role": "provider", "substrate": "native",
                    "runtime_abi": "elastos.provider-stdio/v1", "execution": "native-provider",
                    "provides": "custody", "runtime_only": true
                }),
                "ipfs-provider" => serde_json::json!({
                    "role": "provider", "substrate": "native",
                    "runtime_abi": "elastos.provider-stdio/v1", "execution": "native-provider",
                    "provides": "elastos://ipfs/*"
                }),
                other => panic!("no fixture provider_runtime for {other}"),
            };
            external.insert(
                name.to_string(),
                serde_json::json!({
                    "install_path": format!("bin/{name}"),
                    "provider_runtime": provider_runtime,
                    "platforms": {(elastos_server::setup::detect_platform()): {
                        "install_path": format!("bin/{name}"),
                        "checksum": format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
                    }}
                }),
            );
            installed.push(binary);
        }
        let components = serde_json::to_vec(&serde_json::json!({
            "external": external, "capsules": {}, "profiles": {}
        }))
        .unwrap();
        fs::write(data_dir.join("components.json"), &components).unwrap();
        sign_test_home(data_dir);
        installed
    }

    /// Sign this Home's current components.json into a publisher-signed
    /// release with a trusted source, as an installed Home has. Native
    /// provider starts admit their executable against this release.
    #[cfg(unix)]
    fn sign_test_home(data_dir: &Path) {
        use elastos_common::localhost::{
            publisher_release_head_path, publisher_release_manifest_path,
        };
        use sha2::{Digest as _, Sha256};
        let components = fs::read(data_dir.join("components.json")).unwrap();
        let cid = |bytes: &[u8]| {
            cid::Cid::new_v1(
                0x55,
                cid::multihash::Multihash::<64>::wrap(0x12, &Sha256::digest(bytes)).unwrap(),
            )
            .to_string()
        };
        let descriptor = |bytes: &[u8]| {
            serde_json::json!({
                "cid": cid(bytes), "sha256": hex::encode(Sha256::digest(bytes)), "size": bytes.len()
            })
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        let signed = |payload: serde_json::Value, domain: &str| {
            let (signature, signer_did) = elastos_server::crypto::domain_separated_sign(
                &key,
                domain,
                &serde_json::to_vec(&payload).unwrap(),
            );
            serde_json::to_vec(&serde_json::json!({
                "payload": payload, "signature": signature, "signer_did": signer_did
            }))
            .unwrap()
        };
        let runtime = data_dir.join("runtime");
        let runtime_bytes = b"fixture runtime";
        fs::write(&runtime, runtime_bytes).unwrap();
        let release = signed(
            serde_json::json!({
                "schema": "elastos.release/v1", "version": "0.7.0", "channel": "stable",
                "platforms": {(elastos_server::update::detect_release_platform()): {
                    "binary": descriptor(runtime_bytes), "components": descriptor(&components)
                }}
            }),
            "elastos.release.v1",
        );
        let head = signed(
            serde_json::json!({
                "schema": "elastos.release.head/v1", "version": "0.7.0", "channel": "stable",
                "latest_release_cid": cid(&release),
                "release_sha256": hex::encode(Sha256::digest(&release))
            }),
            "elastos.release.head.v1",
        );
        let head_path = publisher_release_head_path(data_dir);
        fs::create_dir_all(head_path.parent().unwrap()).unwrap();
        fs::write(head_path, &head).unwrap();
        fs::write(publisher_release_manifest_path(data_dir), &release).unwrap();
        fs::write(
            data_dir.join("sources.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema": "elastos.trusted-sources/v1", "default_source": "fixture", "sources": [{
                    "name": "fixture",
                    "publisher_dids": [elastos_server::crypto::encode_signing_key_did(&key)],
                    "channel": "stable", "installed_version": "0.7.0",
                    "install_path": runtime, "head_cid": cid(&head)
                }]
            }))
            .unwrap(),
        )
        .unwrap();
    }

    /// A stdio provider that answers every request with the fixed import CID,
    /// standing in for a kubo-backed ipfs-provider install.
    #[cfg(unix)]
    fn write_mock_ipfs_provider(temp: &TempDir) -> PathBuf {
        let bin_dir = temp.path().join("mock-bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let path = bin_dir.join("ipfs-provider");
        crate::test_support::write_from_child(
            &path,
            format!(
                "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '{{\"status\":\"ok\",\"data\":{{\"cid\":\"%s\"}}}}\\n' '{PROVIDER_HOST_TEST_CID}'\ndone\n"
            ),
            0o700,
        );
        path
    }

    #[cfg(unix)]
    fn custody_status_invocation() -> ProviderInvocation {
        ProviderInvocation {
            // The Runtime is the only source the custody route accepts.
            source: "runtime".to_string(),
            target: "custody".to_string(),
            op: "status".to_string(),
            request: serde_json::json!({"op": "status"}),
            transfer: ProviderTransfer::Json,
            range: None,
            progress: None,
            transport: elastos_runtime::provider::ProviderInvocationTransport::Local,
        }
    }

    /// The exact request a Carrier peer's `provider_invoke` dispatch hands to
    /// `ProviderRegistry::send_raw("content", ..)` for a replica receive.
    #[cfg(unix)]
    fn carrier_replica_import_exact_request(source_endpoint_did: &str) -> serde_json::Value {
        serde_json::json!({
            "op": "import_exact",
            "cid": PROVIDER_HOST_TEST_CID,
            "data": "ZWxhc3Rvcy1yZXBsaWNh",
            "_runtime_invocation": {
                "schema": "elastos.provider.invocation/v1",
                "source": "carrier-availability",
                "target": "content",
                "op": "import_exact",
                "capability": "provider:carrier-availability->content:import_exact",
                "transport": "carrier-provider-plane",
                "carrier": {"source_endpoint_did": source_endpoint_did},
                "transfer": "json",
                "range": serde_json::Value::Null,
                "progress": serde_json::Value::Null,
                "abi": {
                    "schema": "elastos.provider.transfer-abi/v1",
                    "transfer": "json",
                    "transport": "carrier-provider-plane",
                    "range_supported": false,
                    "progress_supported": false,
                    "progress_mode": "none",
                    "transport_native_stream": false,
                    "backpressure": "not_applicable",
                    "cancel_supported": false,
                },
            },
        })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_host_registers_custody_plane_and_publishes_ready_receipt_without_http() {
        let custody_binary = required_provider_host_test_binary(PROVIDER_HOST_TEST_CUSTODY_BIN_ENV);
        let temp = TempDir::new().unwrap();
        let data_dir = provisioned_provider_host_data_dir(&temp);
        let custody_binary = install_signed_custody_provider(&data_dir, &custody_binary);

        let plan = crate::provider_host::ProviderHostPlan::resolve(
            data_dir.clone(),
            custody_binary.to_str().unwrap(),
            &[],
            Some("127.0.0.1:0"),
        )
        .unwrap();
        assert_eq!(plan.provider_names(), vec!["custody-provider"]);

        let host = crate::provider_host::compose(&plan).await.unwrap();
        let receipt_path = host.receipt_path().to_path_buf();

        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
        let (_signing_key, did) = elastos_identity::load_or_create_did(&data_dir).unwrap();
        assert_eq!(receipt["did"], serde_json::Value::String(did));
        assert_eq!(
            receipt["providers"],
            serde_json::json!(["custody-provider"])
        );
        assert!(receipt["carrier_bound"]
            .as_str()
            .unwrap()
            .parse::<std::net::SocketAddr>()
            .is_ok());
        assert!(receipt["started_at"].as_u64().unwrap() > 0);
        assert_eq!(
            fs::metadata(&receipt_path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let status = host
            .registry()
            .invoke_provider(custody_status_invocation())
            .await
            .unwrap();
        assert_eq!(status["status"], "ok");
        assert_eq!(status["data"]["provider"], "custody");

        // The provider host stands up no HTTP or TLS surface at all.
        assert!(!data_dir.join("tls.pem").exists());
        assert!(!data_dir.join("ca.pem").exists());
        assert!(!data_dir.join("runtime-coords.json").exists());

        host.shutdown().await.unwrap();
        assert!(!receipt_path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_host_with_content_replica_set_answers_custody_and_content_targets() {
        let custody_binary = required_provider_host_test_binary(PROVIDER_HOST_TEST_CUSTODY_BIN_ENV);
        let temp = TempDir::new().unwrap();
        let data_dir = provisioned_provider_host_data_dir(&temp);
        let ipfs_binary = write_mock_ipfs_provider(&temp);
        let installed = install_signed_providers(
            &data_dir,
            &[
                ("custody-provider", custody_binary.as_path()),
                ("ipfs-provider", ipfs_binary.as_path()),
            ],
        );
        let (custody_binary, ipfs_binary) = (installed[0].clone(), installed[1].clone());

        let plan = crate::provider_host::ProviderHostPlan::resolve(
            data_dir.clone(),
            custody_binary.to_str().unwrap(),
            std::slice::from_ref(&ipfs_binary.to_string_lossy().into_owned()),
            Some("127.0.0.1:0"),
        )
        .unwrap();
        assert_eq!(
            plan.provider_names(),
            vec!["custody-provider", "ipfs-provider"]
        );

        let host = crate::provider_host::compose(&plan).await.unwrap();
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(host.receipt_path()).unwrap()).unwrap();
        assert_eq!(
            receipt["providers"],
            serde_json::json!(["custody-provider", "ipfs-provider"])
        );

        let status = host
            .registry()
            .invoke_provider(custody_status_invocation())
            .await
            .unwrap();
        assert_eq!(status["status"], "ok");

        let (_signing_key, did) = elastos_identity::load_or_create_did(&data_dir).unwrap();
        let import = host
            .registry()
            .send_raw("content", &carrier_replica_import_exact_request(&did))
            .await
            .unwrap();
        assert_eq!(import["status"], "ok", "{import}");

        let content_status = host
            .registry()
            .send_raw(
                "content",
                &serde_json::json!({"op": "status", "cid": PROVIDER_HOST_TEST_CID}),
            )
            .await
            .unwrap();
        assert_eq!(content_status["status"], "ok", "{content_status}");
        assert_eq!(
            content_status["data"]["availability"]["policy"],
            "carrier_exact_import"
        );

        host.shutdown().await.unwrap();
    }

    #[test]
    fn provider_host_plan_rejects_an_unknown_provider_naming_the_supported_set() {
        let temp = TempDir::new().unwrap();
        let error = crate::provider_host::ProviderHostPlan::resolve(
            temp.path().to_path_buf(),
            "nonexistent-provider",
            &[],
            None,
        )
        .expect_err("an unknown provider name must fail closed");
        let message = error.to_string();
        assert!(message.contains("nonexistent-provider"), "{message}");
        assert!(message.contains("custody-provider"), "{message}");
        assert!(message.contains("availability-provider"), "{message}");
        assert!(message.contains("ipfs-provider"), "{message}");
        assert!(message.contains("chain-provider"), "{message}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn provider_host_custody_without_provisioned_state_names_the_provisioning_command() {
        let custody_binary = required_provider_host_test_binary(PROVIDER_HOST_TEST_CUSTODY_BIN_ENV);
        let temp = TempDir::new().unwrap();
        let data_dir = fs::canonicalize(temp.path()).unwrap().join("data");
        owner_only_test_dir(&data_dir);

        let plan = crate::provider_host::ProviderHostPlan::resolve(
            data_dir,
            custody_binary.to_str().unwrap(),
            &[],
            Some("127.0.0.1:0"),
        )
        .unwrap();
        let error = match crate::provider_host::compose(&plan).await {
            Ok(_) => panic!("an unprovisioned custody node must fail closed"),
            Err(error) => error,
        };
        let message = format!("{error:#}");
        assert!(
            message.contains("elastos protected-content-config provision-custody-node"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn serve_capability_store_keeps_revoke_all_after_restart() {
        let data_dir = TempDir::new().unwrap();
        let resource = capability::ResourceId::new("elastos://content/fetch");
        let token = {
            let store = serve_capability_store(data_dir.path())
                .await
                .expect("serve store");
            let manager = capability::CapabilityManager::load_or_generate(
                data_dir.path(),
                store,
                Arc::new(primitives::audit::AuditLog::new()),
                Arc::new(primitives::metrics::MetricsManager::new()),
            );
            let token = manager.grant(
                "test-capsule",
                resource.clone(),
                capability::Action::Read,
                capability::TokenConstraints::default(),
                None,
            );
            manager
                .validate(
                    &token,
                    "test-capsule",
                    capability::Action::Read,
                    &resource,
                    None,
                )
                .await
                .expect("grant still validates before revoke");
            manager.revoke_all("test restart revoke");
            token
        };

        let store = serve_capability_store(data_dir.path())
            .await
            .expect("reopened serve store");
        let manager = capability::CapabilityManager::load_or_generate(
            data_dir.path(),
            store,
            Arc::new(primitives::audit::AuditLog::new()),
            Arc::new(primitives::metrics::MetricsManager::new()),
        );
        let result = manager
            .validate(
                &token,
                "test-capsule",
                capability::Action::Read,
                &resource,
                None,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(capability::manager::ValidationError::TokenRevoked)
            ),
            "revoked token must stay revoked after restart: {result:?}"
        );
    }

    /// A3-R S3 fix 2: the Home's start applies the pending revocation list.
    /// An end's revoke the store could not save is refused by the restarted
    /// Home's capability store.
    #[tokio::test]
    async fn serve_capability_store_applies_pending_revocations() {
        use elastos_server::api::handlers::settle;
        let data_dir = TempDir::new().unwrap();
        let resource = capability::ResourceId::new("elastos://content/fetch");
        let plane = |store| {
            capability::CapabilityManager::load_or_generate(
                data_dir.path(),
                store,
                Arc::new(primitives::audit::AuditLog::new()),
                Arc::new(primitives::metrics::MetricsManager::new()),
            )
        };
        let store = serve_capability_store(data_dir.path()).await.unwrap();
        let manager = plane(store);
        let pending = capability::pending::PendingRequestStore::new(manager.audit_log().clone());
        let session = session::SessionId::from_string("ended-capsule");
        let request = pending
            .create_request(session, resource.clone(), capability::Action::Read)
            .await;
        let token = manager.grant(
            "ended-capsule",
            resource.clone(),
            capability::Action::Read,
            capability::TokenConstraints::default(),
            None,
        );
        pending
            .grant_request(
                request.id.as_str(),
                token.clone(),
                capability::GrantDuration::Session,
            )
            .await
            .unwrap();
        let store_dir = settle::capability_store_dir(data_dir.path());
        fs::create_dir(store_dir.join("revoked_tokens")).unwrap();
        let settled = settle::settle_and_revoke(
            &pending,
            &manager,
            data_dir.path(),
            "ended-capsule",
            "trapped",
        )
        .await;
        assert!(settled.is_err(), "the save failed: {settled:?}");

        let restarted = plane(serve_capability_store(data_dir.path()).await.unwrap());
        let result = restarted
            .validate(
                &token,
                "ended-capsule",
                capability::Action::Read,
                &resource,
                None,
            )
            .await;
        assert_eq!(
            result,
            Err(capability::manager::ValidationError::TokenRevoked),
            "the restarted Home refuses the unsaved revoke"
        );
    }

    #[test]
    fn model_provider_confinement_refuses_unsupported_os() {
        for os in ["macos", "linux"] {
            assert!(
                super::model_provider_confinement(os).is_ok(),
                "{os} must start the model provider behind its egress filter"
            );
        }
        for os in ["freebsd", "windows", ""] {
            match super::model_provider_confinement(os) {
                Err(elastos_runtime::provider::bridge::BridgeError::InitFailed(reason)) => {
                    assert_eq!(
                        reason, "provider confinement unavailable on this OS",
                        "{os} reason"
                    )
                }
                other => panic!("{os} must refuse model startup, got {other:?}"),
            }
        }
    }

    /// Fix one scratch directory's mode so it does not follow the operator umask.
    #[cfg(target_os = "linux")]
    fn set_scratch_mode(directory: &Path, mode: u32) {
        fs::set_permissions(directory, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Install the probe as the model provider below one scratch data root. The
    /// startup path verifies the binary against that root's manifest and reads
    /// the operator model config below it, so it reaches only scratch files.
    #[cfg(target_os = "linux")]
    fn staged_model_probe() -> StagedModelProbe {
        let scratch = TempDir::new().unwrap();
        // Startup refuses an identity root writable by others, so the probe's
        // own scratch roots are 0700 whatever the operator umask is.
        set_scratch_mode(scratch.path(), 0o700);
        let root = scratch.path().join("data/elastos");
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        for directory in [&root, &scratch.path().join("data")] {
            set_scratch_mode(directory, 0o700);
        }
        let probe = bin.join("model-provider");
        let source = scratch.path().join("probe.rs");
        fs::write(
            &source,
            include_str!("../../elastos-runtime/tests/fixtures/linux_model_seccomp_probe.rs"),
        )
        .unwrap();
        let built = Command::new("rustc")
            .args(["--edition", "2021", "-o"])
            .arg(&probe)
            .arg(&source)
            .output()
            .unwrap();
        assert!(built.status.success(), "probe build failed");
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o755)).unwrap();
        use sha2::Digest as _;
        let checksum = format!(
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(fs::read(&probe).unwrap()))
        );
        // The startup path verifies this manifest entry before it spawns.
        let manifest = serde_json::json!({"external": {"model-provider": {
            "version": "test",
            "install_path": "bin/model-provider",
            "provider_runtime": {
                "role": "provider",
                "substrate": "native",
                "runtime_abi": "elastos.provider-stdio/v1",
                "execution": "native-provider",
                "provides": "elastos://model",
            },
            "platforms": {&elastos_server::setup::detect_platform(): {
                "checksum": checksum,
                "source": probe.to_string_lossy(),
                "strategy": "local-copy",
            }},
        }}, "capsules": {}, "profiles": {}});
        fs::write(
            root.join("components.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        // Startup admits model-provider against this Home's signed release
        // (binaries::resolve_verified_native_provider_binary), as on an
        // installed Home; without one, admission refuses before spawn.
        sign_test_home(&root);
        // One hosted offer answers status without a local model slot.
        let config_root = root.join("providers/model-provider");
        fs::create_dir_all(&config_root).unwrap();
        fs::set_permissions(root.join("providers"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&config_root, fs::Permissions::from_mode(0o700)).unwrap();
        let config = config_root.join("config.json");
        fs::write(
            &config,
            br#"{"offers":[{"id":"offer:test","adapter":{"kind":"open_ai_compatible_text"}}]}"#,
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        StagedModelProbe { scratch, root }
    }

    #[cfg(target_os = "linux")]
    struct StagedModelProbe {
        scratch: TempDir,
        root: PathBuf,
    }

    /// Prove the real Linux startup path starts the model provider through the
    /// egress-filtered spawn: the child it starts reports NO_NEW_PRIVS=1, SECCOMP
    /// mode 2, and an AF_INET socket refused with EPERM. Falsifier B swaps the
    /// call at server_infra.rs:1082 for the plain `spawn`, which installs no
    /// filter, and this test then fails at its `no_new_privs` assertion.
    ///
    /// The child half is the `linux_model_startup_probe` test below: this test
    /// starts one real startup composition in a child process against the
    /// scratch Home that `staged_model_probe` writes.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_model_startup_starts_provider_through_the_egress_filtered_spawn() {
        let probe = staged_model_probe();
        let root = probe.root.clone();
        let Output {
            status,
            stdout,
            stderr,
        } = Command::new(std::env::current_exe().unwrap())
            // The child half is `#[ignore]`d so a plain suite run skips it;
            // this parent names it with `--ignored`.
            .args([
                "--exact",
                "--ignored",
                "--nocapture",
                "server_infra::tests::linux_model_startup_probe",
            ])
            .env("ELASTOS_LINUX_MODEL_PROBE_ROOT", &root)
            .current_dir(probe.scratch.path())
            .env("HOME", probe.scratch.path())
            .env("XDG_DATA_HOME", probe.scratch.path().join("data"))
            .env("TMPDIR", probe.scratch.path())
            .env("ELASTOS_CAPSULE_BIN_DIR", root.join("bin"))
            .env_remove("ELASTOS_MODEL_PROVIDER_CONFIG")
            .env_remove("ELASTOS_MODEL_PROVIDER_CONFIG_PATH")
            // Keep startup warnings: a refused model startup names its cause.
            .env("RUST_LOG", "elastos=warn")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&stderr);
        assert!(
            status.success() && !stderr.contains("panicked") && !stderr.contains("FAILED"),
            "startup probe process failed ({status}): {stderr}"
        );
        let stdout = String::from_utf8(stdout).unwrap();
        // --nocapture puts the child test's own verdict on its stdout.
        assert!(!stdout.contains("FAILED"), "startup probe test failed");
        let facts: serde_json::Value = serde_json::from_str(
            stdout
                .lines()
                .find(|line| line.starts_with('{'))
                .unwrap_or_else(|| panic!("startup probe reported no facts: {stdout}\n{stderr}")),
        )
        .unwrap();
        assert_eq!(facts["data_root"], serde_json::json!(&root));
        // Absent here means startup never registered `elastos://model`.
        assert_eq!(
            facts["registered_route"],
            serde_json::json!("model"),
            "startup did not register the model target\n{stderr}"
        );
        // The child writes one `name=value` line per kernel observation.
        let report = fs::read_to_string(root.join("bin/model-provider.observed"))
            .expect("model provider wrote no observations from the startup route");
        let inherited = report
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            inherited.get("no_new_privs"),
            Some(&"1"),
            "startup child did not inherit NO_NEW_PRIVS: {report}"
        );
        assert_eq!(
            inherited.get("seccomp"),
            Some(&"2"),
            "startup child did not inherit a seccomp filter: {report}"
        );
        assert_eq!(
            inherited.get("inet_socket"),
            Some(&"EPERM"),
            "startup child could open an Internet socket: {report}"
        );
    }

    /// model provider here, so the probe's own file records what that route
    /// bound.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "child half of linux_model_startup_starts_provider_through_the_egress_filtered_spawn; run by the parent"]
    async fn linux_model_startup_probe() {
        // `main` installs these before startup; the test process starts there.
        rustls::crypto::ring::default_provider()
            .install_default()
            .unwrap();
        drop(
            tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .try_init(),
        );
        // The parent passes the exact scratch root, so this process cannot fall
        // back to the real Home.
        let data_dir = PathBuf::from(
            std::env::var_os("ELASTOS_LINUX_MODEL_PROBE_ROOT")
                .expect("probe needs ELASTOS_LINUX_MODEL_PROBE_ROOT"),
        );
        // The gateway profile runs the same startup function and the same model
        // block, without the Home-only host provider this fixture does not stage.
        let mut infrastructure = match setup_gateway_infrastructure().await {
            Ok(infrastructure) => infrastructure,
            Err(error) => panic!("startup failed in {}: {error:#}", data_dir.display()),
        };
        let registration = infrastructure
            .provider_registry
            .registration_for_uri("elastos://model/offers")
            .await
            .map(|registration| registration.route);
        // Stopping the model target shuts the recorded child down.
        infrastructure
            .provider_registry
            .unregister_sub_provider("model")
            .await
            .unwrap();
        if let Some(carrier) = infrastructure.carrier_service.as_mut() {
            carrier.shutdown().await.unwrap();
        }
        drop(infrastructure);
        println!(
            "{}",
            serde_json::json!({"data_root": data_dir, "registered_route": registration})
        );
    }
}
