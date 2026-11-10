//! Core runtime implementation

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::RwLock;

use elastos_common::{CapsuleManifest, CapsuleType, ElastosError, Result};
use elastos_compute::providers::{BridgeHostcall, ComponentProvider};
use elastos_compute::{CapsuleHandle, ComputeProvider};
use elastos_storage::StorageProvider;

use elastos_runtime::provider::ProviderRegistry;
use elastos_runtime::signature::{hash_content, SignatureVerifier};

/// Information about a running capsule (for API responses and lifecycle management)
#[derive(Debug, Clone)]
pub struct RunningCapsuleInfo {
    /// Unique capsule instance ID
    pub id: String,
    /// Capsule name from manifest
    pub name: String,
    /// Current status (running, stopped, etc.)
    pub status: String,
    /// Capsule type (WASM, MicroVM)
    pub capsule_type: CapsuleType,
    /// Handle for stopping the capsule (optional, not all capsules have handles)
    pub handle: Option<CapsuleHandle>,
}

/// Which unsigned local capsules the Runtime admits.
enum UnsignedCapsules {
    /// A source or CI Home with `dev_mode = true`.
    Allowed,
    /// Only capsules setup installed from the signed release of the Home at this data dir.
    InstalledRelease(PathBuf),
    Refused,
}

/// The signer that admitted a capsule: the trusted key that verified it, the
/// installed signed release, or dev_mode's unsigned admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Signer {
    /// A trusted capsule-signing key, named by its `did:key`.
    Key { did: String },
    /// Admitted as a capsule of the installed signed release.
    InstalledRelease,
    /// Admitted unsigned because `dev_mode = true`.
    UnsignedDev,
}

/// The main ElastOS runtime
pub struct Runtime {
    // Keep the storage provider alive for runtime/lifecycle ownership even
    // before direct storage API calls are exposed from this layer.
    _storage: Arc<dyn StorageProvider>,
    /// Compute providers (WASM, crosvm, etc.)
    compute_providers: Vec<Arc<dyn ComputeProvider>>,
    /// Signature verifier for capsule integrity
    signature_verifier: RwLock<SignatureVerifier>,
    /// Unsigned capsule admission; signed capsules always use the verifier.
    unsigned_capsules: RwLock<UnsignedCapsules>,
    /// Provider registry (optional, set when server mode is active)
    provider_registry: RwLock<Option<Arc<ProviderRegistry>>>,
    /// Registry of running capsules (for API queries)
    running_capsules: RwLock<HashMap<String, RunningCapsuleInfo>>,
    /// Reference to the component provider for ABI-specific launch.
    component_provider: Option<Arc<ComponentProvider>>,
    /// What admission decided for each launched capsule, by capsule id.
    admissions: Admissions,
    /// Where the auth state lives, once server mode has set it.
    data_dir: RwLock<Option<std::path::PathBuf>>,
}

/// What admission decided for one launched capsule: who its bridge calls act
/// as, the Human an agent acts for, and the manifest's resource ceilings.
/// The bridge acts with exactly this, and a capsule with no admission
/// context is refused.
#[derive(Debug, Clone)]
pub(crate) struct AdmissionContext {
    pub(crate) actor: Option<String>,
    /// The launcher of an admitted agent. None for an ordinary capsule.
    pub(crate) owner: Option<String>,
    pub(crate) manifest_bounds: Vec<String>,
}

type Admissions = Arc<StdRwLock<HashMap<String, AdmissionContext>>>;

/// The bridge hostcall the Runtime installs for component capsules. Each call
/// acts with the caller's admission context and with nothing the caller says
/// about itself.
fn bridge_hostcall(
    admissions: Admissions,
    registry: Arc<ProviderRegistry>,
    capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
    pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
    data_dir: std::path::PathBuf,
    handle: tokio::runtime::Handle,
) -> BridgeHostcall {
    Arc::new(move |line, capsule_id, _principal_id| {
        let ctx = crate::resource_bridge::BridgeContext::admitted(
            registry.clone(),
            capability_manager.clone(),
            pending_store.clone(),
            capsule_id,
            admitted(&admissions, capsule_id)?,
            data_dir.clone(),
        );
        let response = handle
            .block_on(crate::resource_bridge::handle_component_resource_request(
                line, ctx,
            ))
            .map_err(|err| err.to_string())?;
        serde_json::to_string(&response).map_err(|err| err.to_string())
    })
}

/// The admission context of a launched capsule, or the refusal.
fn admitted(
    admissions: &Admissions,
    capsule_id: &str,
) -> std::result::Result<AdmissionContext, String> {
    let admission = admissions
        .read()
        .ok()
        .and_then(|guard| guard.get(capsule_id).cloned());
    admission.ok_or_else(|| format!("capsule '{capsule_id}' has no admission context"))
}

impl Runtime {
    /// Create a new runtime with a single compute provider (backward compatible)
    pub fn new(storage: Arc<dyn StorageProvider>, compute: Arc<dyn ComputeProvider>) -> Self {
        Self {
            _storage: storage,
            compute_providers: vec![compute],
            signature_verifier: RwLock::new(SignatureVerifier::new()),
            unsigned_capsules: RwLock::new(UnsignedCapsules::Refused),
            provider_registry: RwLock::new(None),
            running_capsules: RwLock::new(HashMap::new()),
            component_provider: None,
            admissions: Arc::new(StdRwLock::new(HashMap::new())),
            data_dir: RwLock::new(None),
        }
    }

    pub fn with_providers_and_component(
        storage: Arc<dyn StorageProvider>,
        compute_providers: Vec<Arc<dyn ComputeProvider>>,
        component_provider: Option<Arc<ComponentProvider>>,
    ) -> Self {
        Self {
            _storage: storage,
            compute_providers,
            signature_verifier: RwLock::new(SignatureVerifier::new()),
            unsigned_capsules: RwLock::new(UnsignedCapsules::Refused),
            provider_registry: RwLock::new(None),
            running_capsules: RwLock::new(HashMap::new()),
            component_provider,
            admissions: Arc::new(StdRwLock::new(HashMap::new())),
            data_dir: RwLock::new(None),
        }
    }

    /// Set the provider registry and capability manager for provider dispatch
    /// and real token minting.
    ///
    /// Also configures the component hostcall so component capsules can
    /// communicate with providers through Runtime-controlled authority.
    pub async fn set_provider_registry(
        &self,
        registry: Arc<ProviderRegistry>,
        capability_manager: Arc<elastos_runtime::capability::CapabilityManager>,
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        data_dir: std::path::PathBuf,
    ) {
        *self.data_dir.write().await = Some(data_dir.clone());
        if let Some(ref component) = self.component_provider {
            component.set_bus_hostcall(bridge_hostcall(
                self.admissions.clone(),
                registry.clone(),
                capability_manager.clone(),
                pending_store.clone(),
                data_dir.clone(),
                tokio::runtime::Handle::current(),
            ));
            tracing::info!("Component resource bridge configured");
        }

        let mut guard = self.provider_registry.write().await;
        *guard = Some(registry);
    }

    /// Override the default local capsule carrier host-call handler.
    ///
    /// Used by attached-runtime execution to route guest calls
    /// through the already-running local runtime API.
    pub fn set_bridge_hostcall(&self, hostcall: BridgeHostcall) {
        if let Some(ref component) = self.component_provider {
            component.set_bus_hostcall(hostcall);
        }
    }

    /// Find a compute provider that supports the given capsule type
    fn get_provider(&self, capsule_type: &CapsuleType) -> Option<Arc<dyn ComputeProvider>> {
        self.compute_providers
            .iter()
            .find(|p| p.supports(capsule_type))
            .cloned()
    }

    fn get_provider_for_manifest(
        &self,
        manifest: &CapsuleManifest,
    ) -> Option<Arc<dyn ComputeProvider>> {
        if manifest.is_component_capsule() {
            return self
                .component_provider
                .as_ref()
                .map(|provider| provider.clone() as Arc<dyn ComputeProvider>);
        }
        if matches!(
            manifest.execution_type(),
            CapsuleType::Wasm
                | CapsuleType::WebProjection
                | CapsuleType::NativeProvider
                | elastos_common::CapsuleType::NativeHost
        ) {
            return None;
        }
        self.get_provider(&manifest.capsule_type)
    }

    /// Configure capsule admission for the Home at `data_dir`.
    ///
    /// An installed signed release always enforces signatures: its publisher
    /// keys and `trusted_keys` verify signed capsules, and an unsigned capsule
    /// is admitted only when setup installed it from that release by CID. Other
    /// Homes admit unsigned capsules only with `dev_mode = true`, which source
    /// and CI Homes set explicitly.
    pub async fn configure_capsule_admission(
        &self,
        data_dir: &Path,
        trusted_keys: &[String],
        dev_mode: bool,
    ) -> Result<()> {
        let installed = crate::setup::installed_release_source(data_dir)
            .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;
        let mut verifier = SignatureVerifier::new();
        for key in trusted_keys {
            verifier.add_trusted_key_hex(key)?;
        }
        for did in installed.iter().flat_map(|source| &source.publisher_dids) {
            let key = crate::crypto::decode_did_key(did)
                .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;
            verifier.add_trusted_key(key)?;
        }
        let trusted_key_count = verifier.trusted_key_count();
        let unsigned = match (installed, dev_mode) {
            (Some(_), _) => UnsignedCapsules::InstalledRelease(data_dir.to_path_buf()),
            (None, true) => UnsignedCapsules::Allowed,
            (None, false) => UnsignedCapsules::Refused,
        };
        match &unsigned {
            UnsignedCapsules::Allowed => tracing::warn!(
                "Capsule signature verification running in dev_mode=true; unsigned local capsules are allowed"
            ),
            UnsignedCapsules::InstalledRelease(_) => tracing::info!(
                "Capsule signatures enforced for the installed release with {} trusted key(s); unsigned capsules only from the signed release{}",
                trusted_key_count,
                if dev_mode { " (config.toml dev_mode does not apply)" } else { "" }
            ),
            UnsignedCapsules::Refused => tracing::info!(
                "Capsule signatures enforced with {} trusted key(s)",
                trusted_key_count
            ),
        }
        *self.signature_verifier.write().await = verifier;
        *self.unsigned_capsules.write().await = unsigned;
        Ok(())
    }

    /// Load and run a capsule from a local directory
    pub async fn run_local(&self, path: &Path, args: Vec<String>) -> Result<CapsuleHandle> {
        self.run_local_with_principal(path, args, None).await
    }

    /// Load and run a capsule from a local directory with an optional runtime
    /// principal for current-user storage alias resolution.
    pub async fn run_local_with_principal(
        &self,
        path: &Path,
        args: Vec<String>,
        principal_id: Option<String>,
    ) -> Result<CapsuleHandle> {
        self.run_local_with_signer(path, args, principal_id)
            .await
            .map(|(handle, _signer)| handle)
    }

    /// Load and run a capsule, also returning the signer admission verified.
    pub(crate) async fn run_local_with_signer(
        &self,
        path: &Path,
        args: Vec<String>,
        principal_id: Option<String>,
    ) -> Result<(CapsuleHandle, Signer)> {
        // Read manifest
        let manifest_path = path.join("capsule.json");
        let manifest_data = tokio::fs::read_to_string(&manifest_path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    ElastosError::InvalidManifest(format!(
                        "capsule.json not found in {}",
                        path.display()
                    ))
                } else {
                    ElastosError::Io(e)
                }
            })?;

        let manifest: CapsuleManifest = serde_json::from_str(&manifest_data).map_err(|e| {
            ElastosError::InvalidManifest(format!("Failed to parse capsule.json: {}", e))
        })?;
        manifest.validate().map_err(ElastosError::InvalidManifest)?;

        // Reject entrypoints that escape the capsule directory
        if manifest.entrypoint.contains("..")
            || std::path::Path::new(&manifest.entrypoint).is_absolute()
        {
            return Err(ElastosError::InvalidManifest(
                "Entrypoint must be a relative path within the capsule directory".into(),
            ));
        }

        tracing::info!(
            "Loading capsule '{}' ({:?})",
            manifest.name,
            manifest.capsule_type
        );

        // Check provider dependencies
        self.check_provider_dependencies(&manifest).await?;

        // Verify signature if verifier is configured
        let signer = self.verify_capsule_signature(&manifest, path).await?;
        crate::component::validate_component_capsule(path, &manifest).await?;
        let admission = self.admit(&manifest, &signer, principal_id).await?;

        // Find a compute provider that supports this capsule type
        let provider = self.get_provider_for_manifest(&manifest).ok_or_else(|| {
            if manifest.is_component_capsule() {
                ElastosError::Compute("No component compute provider is configured".to_string())
            } else {
                ElastosError::Compute(format!(
                    "No compute provider supports capsule type: {:?}",
                    manifest.capsule_type
                ))
            }
        })?;

        // Load capsule
        let mut handle = provider.load(path, manifest).await?;
        if let Ok(mut admissions) = self.admissions.write() {
            admissions.insert(handle.id.0.clone(), admission.clone());
        }
        if handle.manifest.is_component_capsule() {
            if let Some(ref component) = self.component_provider {
                component
                    .set_bridge_principal(&handle.id, admission.actor)
                    .await;
            }
        }

        // Set args on handle before starting
        handle.args = args;

        // Start capsule
        let start = provider.start(&handle).await;
        if handle.manifest.is_component_capsule() {
            if let Some(ref component) = self.component_provider {
                component.clear_bridge_principal(&handle.id).await;
            }
        }
        if let Ok(mut admissions) = self.admissions.write() {
            admissions.remove(&handle.id.0);
        }
        start?;

        Ok((handle, signer))
    }

    /// Admission for one launch. An ordinary capsule acts as its launcher and
    /// names no owner. An agent must be a component signed by a trusted key
    /// and launched by a stored Human with current protection; it acts as its
    /// own principal, minted here, and carries that launcher as the person it
    /// acts for.
    async fn admit(
        &self,
        manifest: &CapsuleManifest,
        signer: &Signer,
        launcher: Option<String>,
    ) -> Result<AdmissionContext> {
        let manifest_bounds = manifest.resource_authority_bounds();
        if manifest.agent.is_none() {
            return Ok(AdmissionContext {
                actor: launcher,
                owner: None,
                manifest_bounds,
            });
        }
        let refuse = |reason: &str| {
            ElastosError::Compute(format!("Agent '{}' is refused: {reason}", manifest.name))
        };
        let Signer::Key { did } = signer else {
            return Err(refuse("no trusted key signed it"));
        };
        if !manifest.is_component_capsule() {
            return Err(refuse("an agent must be a component capsule"));
        }
        let launcher = launcher.ok_or_else(|| refuse("it has no launcher"))?;
        let data_dir = self.data_dir.read().await.clone();
        let data_dir = data_dir.ok_or_else(|| refuse("this Runtime has no auth state"))?;
        let agent = crate::auth::admit_agent_principal(&data_dir, &launcher, did, &manifest.name)
            .map_err(|err| refuse(&err.to_string()))?;
        Ok(AdmissionContext {
            actor: Some(agent.principal_id),
            owner: Some(launcher),
            manifest_bounds,
        })
    }

    /// Check that all providers required by a capsule are registered
    async fn check_provider_dependencies(&self, manifest: &CapsuleManifest) -> Result<()> {
        if let Some(ref providers) = manifest.providers {
            let registry = self.provider_registry.read().await;
            if let Some(ref registry) = *registry {
                for scheme in providers.keys() {
                    if !registry.has_provider(scheme).await {
                        return Err(ElastosError::Compute(format!(
                            "Capsule '{}' requires provider for scheme '{}' which is not registered",
                            manifest.name, scheme
                        )));
                    }
                }
            }
            // If no registry is set, skip check (CLI mode without server)
        }
        Ok(())
    }

    /// Verify capsule signature if verification is enabled
    async fn verify_capsule_signature(
        &self,
        manifest: &CapsuleManifest,
        path: &Path,
    ) -> Result<Signer> {
        if manifest.signature.is_none() {
            return match &*self.unsigned_capsules.read().await {
                UnsignedCapsules::Allowed => {
                    tracing::warn!(
                        "Unsigned capsule '{}' allowed because dev_mode=true",
                        manifest.name
                    );
                    Ok(Signer::UnsignedDev)
                }
                // An agent is named by the key that signed it. The installed
                // release has no signer DID yet (rong-ruling-a5-measure-1945 Q3,
                // gated), so an agent declared there is refused, failing closed.
                UnsignedCapsules::InstalledRelease(_) if manifest.agent.is_some() => {
                    Err(ElastosError::InvalidManifest(format!(
                        "Capsule '{}' declares an agent but no trusted key signed it",
                        manifest.name
                    )))
                }
                UnsignedCapsules::InstalledRelease(data_dir) => {
                    crate::setup::verify_installed_release_capsule(data_dir, &manifest.name, path)
                        .map_err(|e| {
                            ElastosError::InvalidManifest(format!(
                                "Capsule '{}' is unsigned and not from the installed signed release: {e:#}",
                                manifest.name
                            ))
                        })
                        .map(|()| Signer::InstalledRelease)
                }
                UnsignedCapsules::Refused => Err(ElastosError::InvalidManifest(format!(
                    "Capsule '{}' is unsigned; only a source or development Home with dev_mode = true runs unsigned capsules",
                    manifest.name
                ))),
            };
        }

        let verifier = self.signature_verifier.read().await;

        if !verifier.is_enabled() {
            return Err(ElastosError::InvalidManifest(
                "Capsule signature verification has no trusted keys configured".into(),
            ));
        }

        // Compute content hash (hash the entrypoint file)
        let entrypoint_path = path.join(&manifest.entrypoint);
        let content = tokio::fs::read(&entrypoint_path).await.map_err(|e| {
            ElastosError::InvalidManifest(format!(
                "Failed to read entrypoint {}: {}",
                manifest.entrypoint, e
            ))
        })?;
        let content_hash = hash_content(&content);

        // Verify signature; the matched trusted key names the signer.
        let Some(key) = verifier.verify_capsule(manifest, &content_hash)? else {
            return Err(ElastosError::InvalidManifest(
                "Capsule signature verification failed".into(),
            ));
        };
        let did = crate::crypto::encode_did_key(&key)
            .map_err(|e| ElastosError::InvalidManifest(e.to_string()))?;

        tracing::info!("Capsule signature verified successfully by {}", did);
        Ok(Signer::Key { did })
    }

    /// Stop a running capsule
    pub async fn stop(&self, handle: &CapsuleHandle) -> Result<()> {
        // Find the provider that supports this capsule type
        let provider = self
            .get_provider_for_manifest(&handle.manifest)
            .ok_or_else(|| {
                ElastosError::Compute(format!(
                    "No compute provider supports capsule type: {:?}",
                    handle.manifest.capsule_type
                ))
            })?;

        provider.stop(handle).await
    }

    /// Check if a capsule type is supported by any provider
    pub fn supports_capsule_type(&self, capsule_type: &CapsuleType) -> bool {
        self.get_provider(capsule_type).is_some()
    }

    /// Register a running capsule with the runtime
    ///
    /// This is used by external code (like main.rs for MicroVM capsules) to
    /// register capsules that weren't started through Runtime's run_* methods.
    pub async fn register_capsule(&self, info: RunningCapsuleInfo) {
        let mut capsules = self.running_capsules.write().await;
        tracing::info!("Registered capsule '{}' with ID: {}", info.name, info.id);
        capsules.insert(info.id.clone(), info);
    }

    /// Unregister a capsule from the runtime
    pub async fn unregister_capsule(&self, id: &str) {
        let mut capsules = self.running_capsules.write().await;
        if capsules.remove(id).is_some() {
            tracing::info!("Unregistered capsule: {}", id);
        }
    }

    /// List all registered capsules
    pub async fn list_capsules(&self) -> Vec<RunningCapsuleInfo> {
        let capsules = self.running_capsules.read().await;
        capsules.values().cloned().collect()
    }

    /// Get a specific capsule by ID
    pub async fn get_capsule(&self, id: &str) -> Option<RunningCapsuleInfo> {
        let capsules = self.running_capsules.read().await;
        capsules.get(id).cloned()
    }

    /// Update a capsule's status
    pub async fn update_capsule_status(&self, id: &str, status: &str) {
        let mut capsules = self.running_capsules.write().await;
        if let Some(info) = capsules.get_mut(id) {
            info.status = status.to_string();
            tracing::debug!("Updated capsule {} status to: {}", id, status);
        }
    }

    /// Stop a capsule by its ID
    ///
    /// This looks up the capsule in the registry and attempts to stop it.
    /// Returns Ok(true) if stopped, Ok(false) if not found, Err on failure.
    pub async fn stop_capsule_by_id(&self, id: &str) -> Result<bool> {
        // Get capsule info and handle
        let capsule_info = {
            let capsules = self.running_capsules.read().await;
            capsules.get(id).cloned()
        };

        let Some(info) = capsule_info else {
            return Ok(false); // Not found
        };

        // If we have a handle, try to stop via compute provider
        if let Some(handle) = &info.handle {
            // Find the provider that supports this capsule type
            if let Some(provider) = self.get_provider_for_manifest(&handle.manifest) {
                tracing::info!("Stopping capsule '{}' ({})", info.name, id);
                provider.stop(handle).await?;
            }
        }

        // Update status to stopped
        {
            let mut capsules = self.running_capsules.write().await;
            if let Some(info) = capsules.get_mut(id) {
                info.status = "stopped".to_string();
            }
        }

        // Unregister the capsule
        self.unregister_capsule(id).await;

        Ok(true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_trait::async_trait;
    use elastos_common::{
        elastos_bus_v1_wit_sha256, CapsuleId, CapsuleManifest, CapsuleRole, CapsuleStatus,
        CapsuleType, Permissions, ResourceLimits, ELASTOS_BUS_V1_CONTRACT, SCHEMA_V1,
    };
    use elastos_compute::{CapsuleInfo, ComputeProvider};
    use elastos_runtime::capability::pending::GrantDuration;
    use elastos_runtime::capability::{
        CapabilityManager, CapabilityStore, Settler, TokenConstraints,
    };
    use elastos_runtime::primitives::audit::{AuditEvent, AuditLog};
    use elastos_runtime::primitives::metrics::MetricsManager;
    use elastos_runtime::provider::{
        Provider, ProviderError, ProviderRegistry, ResourceRequest, ResourceResponse,
    };
    use elastos_storage::providers::LocalFSProvider;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;
    use wasm_encoder::{
        Component, ComponentImportSection, ComponentTypeRef as EncodedComponentTypeRef,
        ComponentTypeSection, InstanceType,
    };

    /// ADMIT-missing: a bridge call from a capsule with no admission context is
    /// refused before the bridge runs, so nothing is pending and no provider
    /// can be reached. With a context, the same call reaches the bridge.
    #[test]
    fn bridge_hostcall_refuses_a_capsule_with_no_admission_context() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let audit_log = Arc::new(AuditLog::new());
        let capability_manager = Arc::new(CapabilityManager::new(
            Arc::new(CapabilityStore::new()),
            audit_log.clone(),
            Arc::new(MetricsManager::new()),
        ));
        let pending_store =
            Arc::new(elastos_runtime::capability::pending::PendingRequestStore::new(audit_log));
        let admissions: Admissions = Arc::new(StdRwLock::new(HashMap::new()));
        let data_dir = tempfile::tempdir().unwrap();
        let hostcall = bridge_hostcall(
            admissions.clone(),
            Arc::new(ProviderRegistry::new()),
            capability_manager,
            pending_store.clone(),
            data_dir.path().to_path_buf(),
            rt.handle().clone(),
        );
        // Outside the bounds given below, so the control is answered at once
        // instead of waiting for an approval.
        let line = r#"{"id":7,"request":{"type":"request_capability","resource":"localhost://Local/Elsewhere/a.txt","action":"read"}}"#;

        let refused = hostcall(line, "never-admitted", None).expect_err("no admission context");
        assert_eq!(refused, "capsule 'never-admitted' has no admission context");
        assert!(rt.block_on(pending_store.list_pending()).is_empty());

        admissions.write().unwrap().insert(
            "admitted".into(),
            AdmissionContext {
                actor: None,
                owner: None,
                manifest_bounds: vec!["localhost://Local/SharedByLocalUsersAndBots/Home/*".into()],
            },
        );
        let answered = hostcall(line, "admitted", None).expect("an admitted capsule is answered");
        let answered: serde_json::Value = serde_json::from_str(&answered).unwrap();
        assert_eq!(answered["id"], 7, "{answered}");
        assert!(rt.block_on(pending_store.list_pending()).is_empty());
    }

    const ADMIT_OWNER: &str = "person:local:launcher";
    const ADMIT_DID: &str = "did:key:z6MkAgentOne";
    /// `agent:v1:` plus the SHA-256, computed outside this crate, of
    /// "26:elastos.agent-principal/v1,21:person:local:launcher,20:did:key:z6MkAgentOne,11:notes-agent,".
    const ADMIT_AGENT: &str =
        "agent:v1:87073a7f8903007ec4ea33c8cadb59eedf9e156536425861e15ac78566aea786";
    /// sha256(ADMIT_AGENT)[..12], computed outside this crate.
    const ADMIT_AGENT_ROOT: &str = "localhost://UsersAI/72d04445606881899647f0f9";

    fn agent_manifest() -> CapsuleManifest {
        let mut manifest = unsigned_manifest();
        manifest.name = "notes-agent".to_string();
        manifest.bus_contract = Some(ELASTOS_BUS_V1_CONTRACT.to_string());
        manifest.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        manifest
    }

    fn agent_key() -> Signer {
        Signer::Key {
            did: ADMIT_DID.to_string(),
        }
    }

    /// A Runtime in server mode whose auth state holds ADMIT_OWNER as a Human
    /// with current protection.
    async fn admission_runtime() -> (Runtime, tempfile::TempDir) {
        let (runtime, temp) = test_runtime().await;
        *runtime.data_dir.write().await = Some(temp.path().to_path_buf());
        crate::auth::store_test_principal_root_protection(temp.path(), ADMIT_OWNER);
        (runtime, temp)
    }

    fn auth_bytes(temp: &tempfile::TempDir) -> Vec<u8> {
        std::fs::read(crate::auth::auth_state_path(temp.path()).unwrap()).unwrap()
    }

    /// ADMIT-signer and ADMIT-restart: an agent signed by a trusted key and
    /// launched by a protected Human acts as its own minted principal, with
    /// the pinned id and root. Admitting it again changes nothing.
    #[tokio::test]
    async fn admission_mints_a_signed_agent_and_is_stable_across_launches() {
        let (runtime, temp) = admission_runtime().await;
        let manifest = agent_manifest();
        let launcher = Some(ADMIT_OWNER.to_string());

        let first = runtime
            .admit(&manifest, &agent_key(), launcher.clone())
            .await
            .unwrap();

        assert_eq!(first.actor.as_deref(), Some(ADMIT_AGENT));
        assert_eq!(
            first.owner.as_deref(),
            Some(ADMIT_OWNER),
            "ADMIT-owner-carried: an admitted agent carries its launcher"
        );
        assert_eq!(first.manifest_bounds, manifest.resource_authority_bounds());
        let record = crate::auth::stored_principal_record(temp.path(), ADMIT_AGENT)
            .unwrap()
            .expect("the agent record is stored");
        assert_eq!(record.kind, crate::auth::PrincipalKind::Agent);
        assert_eq!(record.localhost_root, ADMIT_AGENT_ROOT);
        let state = crate::auth::load_auth_state(temp.path()).unwrap();
        assert_eq!(
            state
                .principal_root_protections
                .iter()
                .filter(|stored| stored.principal_id == ADMIT_AGENT
                    && stored.localhost_root == ADMIT_AGENT_ROOT)
                .count(),
            1
        );
        let before = auth_bytes(&temp);

        let again = runtime
            .admit(&manifest, &agent_key(), launcher)
            .await
            .unwrap();

        assert_eq!(again.actor.as_deref(), Some(ADMIT_AGENT));
        assert_eq!(
            again.owner.as_deref(),
            Some(ADMIT_OWNER),
            "ADMIT-owner-carried: a second admission carries the same launcher"
        );
        assert_eq!(auth_bytes(&temp), before);
    }

    /// A capsule that declares no agent acts as its launcher, whoever signed
    /// it, and nothing is minted.
    #[tokio::test]
    async fn admission_leaves_an_ordinary_capsule_acting_as_its_launcher() {
        let (runtime, temp) = admission_runtime().await;
        let before = auth_bytes(&temp);
        let mut manifest = agent_manifest();
        manifest.agent = None;

        for launcher in [None, Some("device:did:key:unstored".to_string())] {
            let admission = runtime
                .admit(&manifest, &Signer::UnsignedDev, launcher.clone())
                .await
                .unwrap();
            assert_eq!(admission.actor, launcher);
            assert!(
                admission.owner.is_none(),
                "ADMIT-owner-carried: an ordinary capsule has no owner"
            );
        }

        assert_eq!(auth_bytes(&temp), before);
    }

    /// ADMIT-signer, ADMIT-nolauncher, ADMIT-owner and the microVM refusal:
    /// each refusal names its reason and leaves the auth state byte-identical.
    #[tokio::test]
    async fn admission_refuses_an_agent_that_is_not_signed_launched_and_owned() {
        const UNPROTECTED: &str = "person:local:unprotected";
        for (case, reason) in [
            ("unsigned-dev", "no trusted key signed it"),
            ("installed-release", "no trusted key signed it"),
            ("not-a-component", "an agent must be a component capsule"),
            ("no-launcher", "it has no launcher"),
            ("no-auth-state", "this Runtime has no auth state"),
            ("unstored-launcher", "its launcher is not a stored human"),
            ("agent-launcher", "its launcher is not a stored human"),
            (
                "unprotected-launcher",
                "its launcher has no current protection",
            ),
        ] {
            let (runtime, temp) = admission_runtime().await;
            crate::auth::store_test_human_principal(temp.path(), UNPROTECTED);
            let mut manifest = agent_manifest();
            let mut signer = agent_key();
            let mut launcher = Some(ADMIT_OWNER.to_string());
            match case {
                "unsigned-dev" => signer = Signer::UnsignedDev,
                "installed-release" => signer = Signer::InstalledRelease,
                "not-a-component" => {
                    manifest.bus_contract = None;
                    manifest.capsule_type = CapsuleType::MicroVM;
                }
                "no-launcher" => launcher = None,
                "no-auth-state" => *runtime.data_dir.write().await = None,
                "unstored-launcher" => launcher = Some("device:did:key:unstored".to_string()),
                // A minted agent cannot launch another agent.
                "agent-launcher" => {
                    runtime
                        .admit(&manifest, &signer, launcher.clone())
                        .await
                        .unwrap();
                    manifest.name = "second-agent".to_string();
                    launcher = Some(ADMIT_AGENT.to_string());
                }
                "unprotected-launcher" => launcher = Some(UNPROTECTED.to_string()),
                _ => unreachable!(),
            }
            let before = auth_bytes(&temp);

            let error = runtime
                .admit(&manifest, &signer, launcher)
                .await
                .expect_err(case)
                .to_string();

            assert!(
                error.ends_with(&format!("Agent '{}' is refused: {reason}", manifest.name)),
                "{case}: {error}"
            );
            assert_eq!(auth_bytes(&temp), before, "{case}");
        }
    }

    /// ADMIT-attach: `run_local` carries no launcher, so a signed agent
    /// launched that way is refused before any provider loads it. The same
    /// capsule without the agent declaration loads.
    #[tokio::test]
    async fn run_local_refuses_a_signed_agent_before_the_provider_loads() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        let trusted = elastos_runtime::signature::SigningKey::from_bytes(&[42; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(trusted.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let entrypoint = b"vm image bytes";
        let launch = |name: &str, agent: bool| {
            let mut manifest = unsigned_manifest();
            manifest.name = name.to_string();
            manifest.capsule_type = CapsuleType::MicroVM;
            manifest.entrypoint = "rootfs.ext4".to_string();
            if agent {
                manifest.agent = agent_manifest().agent;
            }
            elastos_runtime::signature::sign_capsule(
                &trusted,
                &mut manifest,
                &hash_content(entrypoint),
            )
            .unwrap();
            let dir = temp_dir.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            std::fs::write(dir.join(&manifest.entrypoint), entrypoint).unwrap();
            dir
        };

        let agent_dir = launch("vm-agent", true);
        let error = runtime
            .run_local(&agent_dir, Vec::new())
            .await
            .expect_err("a signed agent with no launcher")
            .to_string();
        assert!(
            error.ends_with("Agent 'vm-agent' is refused: an agent must be a component capsule"),
            "{error}"
        );
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        let plain_dir = launch("vm-plain", false);
        runtime.run_local(&plain_dir, Vec::new()).await.unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    pub(crate) struct NoopComputeProvider;

    #[async_trait]
    impl ComputeProvider for NoopComputeProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("test-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    struct CountingComputeProvider {
        loads: Arc<AtomicUsize>,
    }

    #[derive(Default)]
    struct BusConformanceProvider {
        requests: Mutex<Vec<serde_json::Value>>,
    }

    #[async_trait]
    impl Provider for BusConformanceProvider {
        async fn handle(
            &self,
            _request: ResourceRequest,
        ) -> std::result::Result<ResourceResponse, ProviderError> {
            Err(ProviderError::Provider(
                "the Bus conformance provider accepts JSON dispatch only".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            vec!["test"]
        }

        fn name(&self) -> &'static str {
            "bus-v1-conformance"
        }

        async fn send_raw(
            &self,
            request: &serde_json::Value,
        ) -> std::result::Result<serde_json::Value, ProviderError> {
            self.requests.lock().await.push(request.clone());
            Ok(serde_json::json!({"status": "ok"}))
        }
    }

    #[async_trait]
    impl ComputeProvider for CountingComputeProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(CapsuleHandle {
                id: CapsuleId::new("counting-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn stop(&self, _handle: &CapsuleHandle) -> Result<()> {
            Ok(())
        }

        async fn status(&self, _handle: &CapsuleHandle) -> Result<CapsuleStatus> {
            Ok(CapsuleStatus::Running)
        }

        async fn info(&self, handle: &CapsuleHandle) -> Result<CapsuleInfo> {
            Ok(CapsuleInfo {
                id: handle.id.clone(),
                name: handle.manifest.name.clone(),
                status: CapsuleStatus::Running,
                memory_used_mb: 0,
            })
        }

        fn supports(&self, _capsule_type: &CapsuleType) -> bool {
            true
        }
    }

    pub(crate) async fn test_runtime() -> (Runtime, tempfile::TempDir) {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let compute = Arc::new(NoopComputeProvider);
        (Runtime::new(storage, compute), temp_dir)
    }

    fn unsigned_manifest() -> CapsuleManifest {
        CapsuleManifest {
            schema: SCHEMA_V1.to_string(),
            version: "0.1.0".to_string(),
            name: "unsigned-test".to_string(),
            description: None,
            author: None,
            role: CapsuleRole::App,
            capsule_type: CapsuleType::Wasm,
            runtime_abi: None,
            bus_contract: None,
            wit_world_sha256: None,
            execution: None,
            projections: Vec::new(),
            entrypoint: "app.wasm".to_string(),
            requires: Vec::new(),
            provides: None,
            authority: None,
            capabilities: Vec::new(),
            interfaces: Vec::new(),
            resources: ResourceLimits::default(),
            permissions: Permissions::default(),
            microvm: None,
            providers: None,
            icon: None,
            viewer: None,
            window_policy: None,
            model_content: None,
            agent: None,
            signature: None,
        }
    }

    fn component_with_extra_import() -> Vec<u8> {
        let mut types = ComponentTypeSection::new();
        types.instance(&InstanceType::new());

        let mut imports = ComponentImportSection::new();
        imports.import(
            "wasi:filesystem/types@0.2.0",
            EncodedComponentTypeRef::Instance(0),
        );

        let mut component = Component::new();
        component.section(&types);
        component.section(&imports);
        component.finish()
    }

    #[tokio::test]
    async fn home_without_installed_release_runs_unsigned_capsules_only_in_dev_mode() {
        let (runtime, temp_dir) = test_runtime().await;
        for dev_mode in [false, true] {
            runtime
                .configure_capsule_admission(temp_dir.path(), &[], dev_mode)
                .await
                .unwrap();
            let result = runtime
                .verify_capsule_signature(&unsigned_manifest(), temp_dir.path())
                .await;
            assert_eq!(result.is_ok(), dev_mode, "{result:?}");
        }
    }

    /// An installed Home whose config.toml still says `dev_mode = true` (the
    /// earlier default) admits only its signed release's capsules and capsules
    /// signed by the release publisher.
    #[tokio::test]
    async fn installed_release_refuses_unsigned_and_foreign_signed_local_capsules() {
        let mut home = crate::installed_release::tests::Fixture::new();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let manifest_json = std::fs::read(fixture.join("capsule.json")).unwrap();
        let manifest: CapsuleManifest = serde_json::from_slice(&manifest_json).unwrap();
        let name = manifest.name.clone();
        let entrypoint = b"component bytes";
        let install = |dir: &Path| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("capsule.json"), &manifest_json).unwrap();
            std::fs::write(dir.join(&manifest.entrypoint), entrypoint).unwrap();
        };
        let (cid, sha256) = ("bafkreirelease", "ab".repeat(32));
        std::fs::write(
            home.data.join("components.json"),
            serde_json::to_vec(&serde_json::json!({
                "external": {(&name): {
                    "install_path": format!("capsules/{name}"),
                    "platforms": {(crate::setup::detect_platform()): {
                        "cid": cid, "checksum": format!("sha256:{sha256}"),
                        "extract_path": format!("capsules/{name}")
                    }}
                }},
                "capsules": {(&name): {"cid": cid, "sha256": sha256}},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
        home.bind_components();
        let release_dir = home.data.join("capsules").join(&name);
        install(&release_dir);
        std::fs::write(release_dir.join(".elastos-cid"), cid).unwrap();
        std::fs::write(release_dir.join(".elastos-artifact-sha256"), &sha256).unwrap();
        let local_dir = home.data.join("local").join(&name);
        install(&local_dir);

        let (runtime, _storage) = test_runtime().await;
        runtime
            .configure_capsule_admission(&home.data, &[], true)
            .await
            .unwrap();
        // The installed signed release is named as such, not as a key or dev.
        assert_eq!(
            runtime
                .verify_capsule_signature(&manifest, &release_dir)
                .await
                .unwrap(),
            Signer::InstalledRelease
        );
        let error = runtime
            .verify_capsule_signature(&manifest, &local_dir)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not from the installed signed release"),
            "{error}"
        );
        // A5-S2b: an agent declared on the installed release is refused.
        let mut declared = manifest.clone();
        declared.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        let error = runtime
            .verify_capsule_signature(&declared, &release_dir)
            .await
            .unwrap_err();
        let expected = format!(
            "Capsule '{}' declares an agent but no trusted key signed it",
            declared.name
        );
        assert!(error.to_string().contains(&expected), "{error}");

        let signed_by = |key: u8| {
            let mut signed = manifest.clone();
            elastos_runtime::signature::sign_capsule(
                &elastos_runtime::signature::SigningKey::from_bytes(&[key; 32]),
                &mut signed,
                &hash_content(entrypoint),
            )
            .unwrap();
            signed
        };
        // The fixture release is signed by key 71.
        runtime
            .verify_capsule_signature(&signed_by(71), &local_dir)
            .await
            .unwrap();
        let error = runtime
            .verify_capsule_signature(&signed_by(9), &local_dir)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");

        // A release capsule whose CID receipt no longer matches is refused too.
        std::fs::write(release_dir.join(".elastos-cid"), "bafkreiother").unwrap();
        assert!(runtime
            .verify_capsule_signature(&manifest, &release_dir)
            .await
            .is_err());
    }

    /// A signed capsule names its signer by the matched key's DID; dev_mode's
    /// unsigned admission is named as such.
    #[tokio::test]
    async fn verify_capsule_signature_names_the_matched_signer() {
        let (runtime, temp_dir) = test_runtime().await;
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[71; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let dir = temp_dir.path().join("signed-capsule");
        std::fs::create_dir_all(&dir).unwrap();
        let entrypoint = b"entrypoint bytes";
        std::fs::write(dir.join("main.wasm"), entrypoint).unwrap();
        let mut manifest = unsigned_manifest();
        manifest.entrypoint = "main.wasm".to_string();
        manifest.agent = Some(elastos_common::AgentDeclaration {
            kind: elastos_common::AgentKind::Agent,
        });
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(entrypoint))
            .unwrap();

        let expected_did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        let signer = runtime
            .verify_capsule_signature(&manifest, &dir)
            .await
            .unwrap();
        assert_eq!(signer, Signer::Key { did: expected_did });

        // The unsigned capsule is named unsigned by dev_mode's admission, and
        // dev_mode admits a declared agent unsigned.
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        manifest.signature = None;
        for capsule in [unsigned_manifest(), manifest] {
            assert_eq!(
                runtime
                    .verify_capsule_signature(&capsule, &dir)
                    .await
                    .unwrap(),
                Signer::UnsignedDev
            );
        }
    }

    /// A Home with no signed release, dev_mode off and one trusted key refuses
    /// an unsigned capsule, a capsule signed by another key, and a signed
    /// capsule whose entrypoint changed. The refusal happens at launch, before
    /// a compute provider loads it. The trusted key's capsule is loaded.
    #[tokio::test]
    async fn launch_refuses_untrusted_signers_before_the_provider_loads() {
        async fn launch(
            runtime: &Runtime,
            dir: &Path,
            manifest: &CapsuleManifest,
            entrypoint: &[u8],
        ) -> Result<CapsuleHandle> {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
            std::fs::write(dir.join(&manifest.entrypoint), entrypoint).unwrap();
            runtime.run_local(dir, Vec::new()).await
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        let trusted = elastos_runtime::signature::SigningKey::from_bytes(&[42; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(trusted.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();

        let entrypoint = b"vm image bytes";
        let mut manifest = unsigned_manifest();
        manifest.name = "foreign-vm".to_string();
        manifest.capsule_type = CapsuleType::MicroVM;
        manifest.entrypoint = "rootfs.ext4".to_string();
        let signed_by = |key: &elastos_runtime::signature::SigningKey| {
            let mut signed = manifest.clone();
            elastos_runtime::signature::sign_capsule(key, &mut signed, &hash_content(entrypoint))
                .unwrap();
            signed
        };
        let dir = temp_dir.path().join("foreign-vm");

        let error = launch(&runtime, &dir, &manifest, entrypoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("is unsigned"), "{error}");
        let foreign = elastos_runtime::signature::SigningKey::from_bytes(&[9; 32]);
        let error = launch(&runtime, &dir, &signed_by(&foreign), entrypoint)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");
        let error = launch(&runtime, &dir, &signed_by(&trusted), b"changed image")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        launch(&runtime, &dir, &signed_by(&trusted), entrypoint)
            .await
            .unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn descriptive_execution_types_refuse_generic_compute() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let runtime = Runtime::new(
            storage,
            Arc::new(CountingComputeProvider {
                loads: loads.clone(),
            }),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        for source in [
            include_str!("../../../../templates/capsules/web-app/capsule.json"),
            include_str!("../../../../templates/capsules/provider-contract/capsule.json"),
            include_str!("../../../../capsules/model-provider/capsule.json"),
            include_str!("../../../../capsules/home/capsule.json"),
            include_str!("../../../capsules/shell/capsule.json"),
        ] {
            let manifest: CapsuleManifest = serde_json::from_str(source).unwrap();
            manifest.validate().unwrap();
            let capsule_dir = temp_dir.path().join(&manifest.name);
            std::fs::create_dir_all(
                capsule_dir.join(std::path::Path::new(&manifest.entrypoint).parent().unwrap()),
            )
            .unwrap();
            std::fs::write(
                capsule_dir.join(&manifest.entrypoint),
                b"untrusted artifact",
            )
            .unwrap();
            std::fs::write(capsule_dir.join("capsule.json"), source).unwrap();
            assert!(runtime.get_provider_for_manifest(&manifest).is_none());
            let error = runtime
                .run_local(&capsule_dir, Vec::new())
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("No compute provider supports"),
                "{error}"
            );
        }
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn component_import_validation_fails_before_provider_load() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let loads = Arc::new(AtomicUsize::new(0));
        let compute = Arc::new(CountingComputeProvider {
            loads: loads.clone(),
        });
        let runtime = Runtime::new(storage, compute);
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();

        let capsule_dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("app.component.wasm"),
            component_with_extra_import(),
        )
        .unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            format!(
                r#"{{
                    "schema": "elastos.capsule/v1",
                    "version": "0.1.0",
                    "name": "bad-component",
                    "role": "app",
                    "type": "wasm",
                    "runtime_abi": "elastos.component/v1",
                    "bus_contract": "{}",
                    "wit_world_sha256": "{}",
                    "execution": "component",
                    "projections": ["cli"],
                    "entrypoint": "app.component.wasm"
                }}"#,
                ELASTOS_BUS_V1_CONTRACT,
                elastos_bus_v1_wit_sha256()
            ),
        )
        .unwrap();

        let err = runtime
            .run_local_with_principal(&capsule_dir, Vec::new(), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("component import"));
        assert_eq!(loads.load(Ordering::SeqCst), 0);
    }

    /// A Runtime with the component provider, the real resource bridge, and a
    /// person whose root has principal-root protection, as on a Home.
    struct AgentHostRuntime {
        runtime: Arc<Runtime>,
        capability_manager: Arc<CapabilityManager>,
        pending_store: Arc<elastos_runtime::capability::pending::PendingRequestStore>,
        audit_log: Arc<AuditLog>,
        data_dir: std::path::PathBuf,
        _temp: tempfile::TempDir,
    }

    const AGENT_HOST_PERSON: &str = "person:local:agent-host-e2e";

    async fn agent_host_runtime() -> AgentHostRuntime {
        let temp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp.path().join("storage"))
                .await
                .unwrap(),
        );
        let component_provider = Arc::new(ComponentProvider::new());
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(component_provider),
        ));
        runtime
            .configure_capsule_admission(temp.path(), &[], true)
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
        let data_dir = temp.path().join("runtime-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        crate::auth::store_test_principal_root_protection(&data_dir, AGENT_HOST_PERSON);
        runtime
            .set_provider_registry(
                Arc::new(ProviderRegistry::new()),
                capability_manager.clone(),
                pending_store.clone(),
                data_dir.clone(),
            )
            .await;
        AgentHostRuntime {
            runtime,
            capability_manager,
            pending_store,
            audit_log,
            data_dir,
            _temp: temp,
        }
    }

    fn agent_host_journal() -> (String, String) {
        let root = crate::auth::principal_localhost_root(AGENT_HOST_PERSON);
        let journal = format!("{root}/.AppData/Agents/agent-host/tasks/demo/journal");
        (root, journal)
    }

    fn launch_agent_host(
        fx: &AgentHostRuntime,
    ) -> tokio::task::JoinHandle<elastos_common::Result<elastos_compute::CapsuleHandle>> {
        let runtime = fx.runtime.clone();
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples/agent-host");
        tokio::spawn(async move {
            runtime
                .run_local_with_principal(&dir, Vec::new(), Some(AGENT_HOST_PERSON.to_string()))
                .await
        })
    }

    async fn next_pending(
        store: &elastos_runtime::capability::pending::PendingRequestStore,
    ) -> elastos_runtime::capability::pending::PendingCapabilityRequest {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Some(request) = store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the agent host must ask for a journal grant")
    }

    fn component_invoke_outcomes(audit_log: &AuditLog) -> Vec<(String, String)> {
        audit_log
            .recent_events(100)
            .iter()
            .filter_map(|event| match event {
                AuditEvent::Custom {
                    event_type,
                    details,
                } if event_type == "component.invoke.completed" => Some((
                    details["operation"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    details["outcome"].as_str().unwrap_or_default().to_string(),
                )),
                _ => None,
            })
            .collect()
    }

    /// The whole S3 route in one process: the guest asks for its two grants,
    /// the shell (this test) grants them, the guest writes its journal through
    /// the real bridge with a revision precondition, and reads it back.
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_writes_and_reads_its_journal_through_the_real_bridge() {
        let fx = agent_host_runtime().await;
        let (root, journal) = agent_host_journal();
        let launch = launch_agent_host(&fx);
        let mut asked = Vec::new();
        for _ in 0..2 {
            let pending = next_pending(&fx.pending_store).await;
            asked.push((pending.resource.as_str().to_string(), pending.action));
            let token = fx.capability_manager.grant(
                pending.session_id.as_str(),
                pending.resource.clone(),
                pending.action,
                TokenConstraints::default(),
                None,
            );
            fx.pending_store
                .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish after its grants")
            .expect("the launch task must not panic")
            .expect("the agent host must write and read back its journal");
        assert_eq!(
            asked,
            vec![
                (journal.clone(), elastos_runtime::capability::Action::Write),
                (journal.clone(), elastos_runtime::capability::Action::Read),
            ]
        );
        assert!(fx.pending_store.list_pending().await.is_empty());

        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(
            !raw.windows(4).any(|window| window == b"EAHJ"),
            "stored encrypted"
        );
        let plain = crate::auth::read_principal_root_object(
            &fx.data_dir,
            AGENT_HOST_PERSON,
            &root,
            &journal,
            &path,
        )
        .unwrap();
        assert_eq!(&plain[..4], b"EAHJ");
        assert_eq!(plain[4..6], 2u16.to_le_bytes());
        let outcomes = component_invoke_outcomes(&fx.audit_log);
        assert!(
            outcomes.contains(&("write".to_string(), "ok".to_string())),
            "{outcomes:?}"
        );
        assert!(
            outcomes.contains(&("read".to_string(), "ok".to_string())),
            "{outcomes:?}"
        );
    }

    /// A journal written by the agent host's format 1 encoder (examples/
    /// agent-host at f873957): two turns, a person's "goal\nship it", a goal
    /// record and a read.
    const AGENT_HOST_FORMAT_1_JOURNAL: &[&str] = &[
        "4541484a010001000000000000000000000000000000000000000000000000000000000000000000",
        "000000000000000000000000000000000008000000012500000001011f000000596f752061726520",
        "74686520456c6173744f53206167656e7420686f73742ea02b08ad6c00bb31f647037293207751f5",
        "3c2263c8327d802d0366362842eae0010b00000002030500000068656c6c6fe95bec7ef4c055b5ac",
        "9bd4132a121f4b80fee6f9e9ab1840c2b9987db191557d012300000001021d0000005265706c7920",
        "696e206f6e652073686f7274207061726167726170682ee0d8f303b4006e394934144da53d29f29f",
        "d5b7af273f5049ee9adfb35ee3e16a011100000002030b0000007365636f6e64207475726e3c58cd",
        "0c1acd922f79f72b8863e82f6e5b17bc062114e1c3424e3361521380e7012b000000010225000000",
        "4b656570207468652066697273742073797374656d206c696e6520756e6368616e6765642e1f2116",
        "24b9d75a3b0e9be6368b55c6910e9e32513e8604c8ebb90c2df05e969d011200000002030c000000",
        "676f616c0a73686970206974989306519e8b7d7906f58012c704d5e9235617efa2bf2a905644396e",
        "a975da40011a000000020314000000676f616c0a66696e69736820746865206e6f7465afa8d8a679",
        "d52cb425643fc8d448d7edea3d8eb3ec9ab24c3b77063190a654b1017a0000000209740000003120",
        "62366139386439636539613264393134393238386661336466343264333737633365343237333761",
        "666463646166373134653333633061313030623531303630206c6f63616c686f73743a2f2f557365",
        "72732f73656c662f446f63756d656e74732f6e6f7465732e7478740a616c7068610a488b95a013ae",
        "a1d802a5c30e7d04ecfa818ba6e06b0c028fa53f8383a013674a488b95a013aea1d802a5c30e7d04",
        "ecfa818ba6e06b0c028fa53f8383a013674a",
    ];

    /// A task whose stored journal is format 1: the guest's run fails with
    /// exactly the text the person sees, and the stored object is not touched.
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_refuses_a_format_1_journal_with_its_reason() {
        let fx = agent_host_runtime().await;
        let (root, journal) = agent_host_journal();
        let hex: String = AGENT_HOST_FORMAT_1_JOURNAL.concat();
        let old: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).unwrap())
            .collect();
        assert_eq!(old[4..6], 1u16.to_le_bytes());
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        crate::auth::write_principal_root_object(
            &fx.data_dir,
            AGENT_HOST_PERSON,
            &root,
            &journal,
            &path,
            &old,
        )
        .unwrap();
        let launch = launch_agent_host(&fx);
        for _ in 0..2 {
            let pending = next_pending(&fx.pending_store).await;
            let token = fx.capability_manager.grant(
                pending.session_id.as_str(),
                pending.resource.clone(),
                pending.action,
                TokenConstraints::default(),
                None,
            );
            fx.pending_store
                .grant_request(pending.id.as_str(), token, GrantDuration::Session)
                .await
                .unwrap();
        }
        let error = tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish")
            .expect("the launch task must not panic")
            .expect_err("a format 1 journal must stop the task");
        assert!(
            error
                .to_string()
                .contains("journal format 1 not supported; start a new task"),
            "{error}"
        );
        let stored = crate::auth::read_principal_root_object(
            &fx.data_dir,
            AGENT_HOST_PERSON,
            &root,
            &journal,
            &path,
        )
        .unwrap();
        assert_eq!(stored, old, "the old object is not touched");
    }

    /// The shell denies both requests: the guest finishes, sends no resource
    /// call, and nothing is stored.
    #[tokio::test]
    #[ignore = "loads examples/agent-host/agent-host.component.wasm; run examples/agent-host/run-e2e.sh"]
    async fn the_agent_host_stores_nothing_when_its_journal_grants_are_denied() {
        let fx = agent_host_runtime().await;
        let (_root, journal) = agent_host_journal();
        let launch = launch_agent_host(&fx);
        for _ in 0..2 {
            let pending = next_pending(&fx.pending_store).await;
            assert_eq!(pending.resource.as_str(), journal);
            fx.pending_store
                .deny_request_by(pending.id.as_str(), "not now", Settler::Shell)
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), launch)
            .await
            .expect("the agent host must finish after the denials")
            .expect("the launch task must not panic")
            .expect("a denied agent host still finishes cleanly");
        let path =
            elastos_common::localhost::rooted_localhost_fs_path(&fx.data_dir, &journal).unwrap();
        assert!(!path.exists());
        assert!(component_invoke_outcomes(&fx.audit_log).is_empty());
    }

    #[tokio::test]
    async fn component_conformance_exercises_bus_authorization_dispatch_and_audit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let component_provider = Arc::new(ComponentProvider::new());
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(component_provider.clone()),
        ));
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
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
        let registry = Arc::new(ProviderRegistry::new());
        let provider = Arc::new(BusConformanceProvider::default());
        registry.register(provider.clone()).await;
        runtime
            .set_provider_registry(
                registry,
                capability_manager.clone(),
                pending_store.clone(),
                temp_dir.path().join("runtime-data"),
            )
            .await;

        let fixture_dir =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let launch_runtime = runtime.clone();
        let launch_fixture = fixture_dir.clone();
        let launch = tokio::spawn(async move {
            launch_runtime
                .run_local_with_principal(
                    &launch_fixture,
                    Vec::new(),
                    Some("person:local:bus-conformance".to_string()),
                )
                .await
        });

        let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("component must create a pending capability request");

        assert_eq!(pending.resource.as_str(), "elastos://test/bus/probe");
        assert_eq!(pending.action, elastos_runtime::capability::Action::Read);
        assert_eq!(pending.reason, "verify the Component-to-Bus authority path");
        assert!(pending.session_id.as_str().starts_with("component-"));

        let token = capability_manager.grant(
            pending.session_id.as_str(),
            pending.resource.clone(),
            pending.action,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(pending.id.as_str(), token, GrantDuration::Session)
            .await
            .unwrap();

        let handle = tokio::time::timeout(std::time::Duration::from_secs(5), launch)
            .await
            .expect("component must finish after the grant")
            .expect("component launch task must not panic")
            .expect("component must complete the Bus conformance flow");
        assert_eq!(handle.manifest.name, "bus-v1-conformance");

        let requests = provider.requests.lock().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0]["op"], "read");
        assert_eq!(requests[0]["probe"], "bus-v1-conformance");
        drop(requests);

        let events = audit_log.recent_events(32);
        assert!(events.iter().any(|event| matches!(
            event,
            AuditEvent::CapabilityRequested { resource, .. }
                if resource == "elastos://test/bus/probe"
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            AuditEvent::CapabilityUse { capsule_id, success: true, .. }
                if capsule_id == pending.session_id.as_str()
        )));
        let requested_audit = events.iter().find_map(|event| match event {
            AuditEvent::Custom {
                event_type,
                details,
            } if event_type == "component.invoke.requested" => {
                details.get("audit_id").and_then(|value| value.as_str())
            }
            _ => None,
        });
        let completed_audit = events.iter().find_map(|event| match event {
            AuditEvent::Custom {
                event_type,
                details,
            } if event_type == "component.invoke.completed" => {
                details.get("audit_id").and_then(|value| value.as_str())
            }
            _ => None,
        });
        assert!(requested_audit.is_some());
        assert_eq!(requested_audit, completed_audit);

        let denied_runtime = runtime.clone();
        let denied_fixture = fixture_dir.clone();
        let denied_launch = tokio::spawn(async move {
            denied_runtime
                .run_local_with_principal(
                    &denied_fixture,
                    Vec::new(),
                    Some("person:local:bus-conformance".to_string()),
                )
                .await
        });
        let denied_pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("second component activation must request a capability");
        let wrong_action_token = capability_manager.grant(
            denied_pending.session_id.as_str(),
            denied_pending.resource.clone(),
            elastos_runtime::capability::Action::Write,
            TokenConstraints::default(),
            None,
        );
        pending_store
            .grant_request(
                denied_pending.id.as_str(),
                wrong_action_token,
                GrantDuration::Session,
            )
            .await
            .unwrap();

        let denied = tokio::time::timeout(std::time::Duration::from_secs(5), denied_launch)
            .await
            .expect("denied component activation must finish")
            .expect("denied component task must not panic")
            .expect_err("wrong-action grant must not authorize provider dispatch");
        assert!(denied.to_string().contains("Component capsule denied"));
        assert_eq!(provider.requests.lock().await.len(), 1);
        assert!(audit_log.recent_events(64).iter().any(|event| matches!(
            event,
            AuditEvent::Custom { event_type, details }
                if event_type == "component.invoke.completed"
                    && details["capsule_id"] == denied_pending.session_id.as_str()
                    && details["outcome"] == "denied"
        )));
        assert!(matches!(
            component_provider.status(&handle).await,
            Err(ElastosError::CapsuleNotFound(_))
        ));
    }
}
