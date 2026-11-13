//! Core runtime implementation

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};
use tokio::sync::RwLock;

use crate::bundle_admission::{self, AcceptedSignature, AdmittedBundle, BundleKind, BundleRefusal};
use elastos_bundle_identity::{checked_bundle_within, Budget, LabCid};
use elastos_common::{AuthorityBound, CapsuleManifest, CapsuleType, ElastosError, Result};
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
    /// Per-launch manifest capability ceilings for capsule bridge requests.
    bridge_manifest_capabilities: Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>>,
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
            bridge_manifest_capabilities: Arc::new(StdRwLock::new(HashMap::new())),
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
            bridge_manifest_capabilities: Arc::new(StdRwLock::new(HashMap::new())),
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
        if let Some(ref component) = self.component_provider {
            let host_reg = registry.clone();
            let host_cap_mgr = capability_manager.clone();
            let host_pending = pending_store.clone();
            let host_data_dir = data_dir.clone();
            let host_manifest_capabilities = self.bridge_manifest_capabilities.clone();
            let host_handle = tokio::runtime::Handle::current();
            component.set_bus_hostcall(Arc::new(move |line, capsule_id, principal_id| {
                let manifest_capabilities = host_manifest_capabilities
                    .read()
                    .ok()
                    .and_then(|guard| guard.get(capsule_id).cloned())
                    .unwrap_or_default();
                let ctx = crate::resource_bridge::BridgeContext {
                    provider_registry: host_reg.clone(),
                    capability_manager: host_cap_mgr.clone(),
                    pending_store: host_pending.clone(),
                    capsule_id: capsule_id.to_string(),
                    principal_id: principal_id.map(ToOwned::to_owned),
                    manifest_capabilities,
                    data_dir: Some(host_data_dir.clone()),
                };
                let response = host_handle
                    .block_on(crate::resource_bridge::handle_component_resource_request(
                        line, ctx,
                    ))
                    .map_err(|err| err.to_string())?;
                serde_json::to_string(&response).map_err(|err| err.to_string())
            }));
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

    /// Check a bundle's signature file against the keys this Home trusts:
    /// the same verifier, with the same keys, as every other admission here.
    pub async fn check_bundle_signature(
        &self,
        file: &Path,
        cid: &LabCid,
    ) -> std::result::Result<AcceptedSignature, BundleRefusal> {
        let verifier = self.signature_verifier.read().await;
        bundle_admission::check_bundle_signature(file, cid, &verifier)
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

        // A component's entrypoint is read once. The signature check, the import
        // check and the compiler below all use these same bytes.
        let admitted = if manifest.is_component_capsule() {
            Some(crate::component::read_admitted_entrypoint(path, &manifest).await?)
        } else {
            None
        };

        // Verify signature if verifier is configured
        let signer = self
            .verify_capsule_signature(&manifest, path, admitted.as_deref())
            .await?;
        if let Some(bytes) = &admitted {
            crate::component::validate_component_imports(bytes)
                .map_err(ElastosError::InvalidManifest)?;
        }

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
        // A component is always compiled from the bytes checked above. The
        // provider's own `load(path)` reads the file itself and checks nothing,
        // so it is for capsules that are not components.
        let mut handle = match (admitted, &self.component_provider) {
            (Some(bytes), Some(component)) => component.load_admitted(bytes, manifest).await?,
            (Some(_), None) => {
                return Err(ElastosError::Compute(
                    "No component compute provider is configured".to_string(),
                ))
            }
            (None, _) => provider.load(path, manifest).await?,
        };
        self.start_loaded(provider, &mut handle, args, principal_id)
            .await?;

        Ok((handle, signer))
    }

    /// Start the bundle that the Home at `data_dir` holds under the name
    /// `cid`, and return who signed it.
    ///
    /// The bundle is a program, and it is what starts; or it is content, and
    /// then what starts is the one program of the page that content pins:
    /// content pins exactly its viewer, a page, and a page pins exactly its
    /// program, the core. The content and the page get no instance, and the
    /// handle returned is the core's. A page is not started by its own CID.
    /// Under a program only programs may be pinned.
    ///
    /// Nothing in the store is trusted. The slot is walked again under the
    /// staging limits and must recompute to `cid`; the signature file that is
    /// beside it now must pass the one signature check again, and its signer
    /// is the one returned; the manifest must be one a start by CID takes;
    /// and the component that is compiled is the bytes the walk of its
    /// bundle read, never a second read of the file. A missing slot is a
    /// refusal: nothing is fetched.
    ///
    /// What starts may ask for no more than its own signed manifest asks
    /// for. Its ceiling is filled like every capsule's, from the one bounds
    /// function, and for a manifest this start admits that is its `asks`
    /// and nothing else. A manifest without asks gives an empty ceiling,
    /// and that capsule is also loaded sealed: the component provider
    /// refuses its every call to the bridge before any handler sees it. A
    /// manifest with asks is loaded unsealed, so that it can ask; the asks
    /// grant nothing, and the bridge refuses whatever is beyond them.
    ///
    /// A manifest's requirements must each pin a bundle by CID, and every
    /// pinned bundle, and every bundle those pin, must be in the store and
    /// pass the same checks, under its own signature and inside the one
    /// walk budget they all share, before anything starts. A pinned bundle
    /// is checked and nothing more, the core under content aside: it is not
    /// started, and the capsule that starts gets no way to reach it or its
    /// bytes, the content's included. A bundle that two pins
    /// reach is checked and counted once. Who is trusted is read once for
    /// the whole start.
    pub async fn run_by_bundle(
        &self,
        data_dir: &Path,
        cid: &str,
        args: Vec<String>,
        principal_id: Option<String>,
    ) -> std::result::Result<(CapsuleHandle, AcceptedSignature), BundleRefusal> {
        let budget = bundle_admission::BUNDLE_WALK_BUDGET;
        self.run_by_bundle_observed(data_dir, cid, args, principal_id, budget, |_| {})
            .await
    }

    /// [`Runtime::run_by_bundle`] under `budget`, telling `after_walk` each
    /// time the one walk of a bundle's slot is done, with that bundle's CID.
    /// Tests change the slot at that moment, as another process could, and
    /// give a budget small enough to reach.
    pub(crate) async fn run_by_bundle_observed(
        &self,
        data_dir: &Path,
        cid: &str,
        args: Vec<String>,
        principal_id: Option<String>,
        budget: Budget,
        mut after_walk: impl FnMut(&LabCid),
    ) -> std::result::Result<(CapsuleHandle, AcceptedSignature), BundleRefusal> {
        let asked: LabCid = cid
            .parse()
            .map_err(|_| BundleRefusal::CidFormInvalid(cid.to_string()))?;
        // One budget for the bundle asked for and every bundle pinned below
        // it: the files and bytes each walk takes in come off what the next
        // may take.
        let mut left = budget;
        // Who is trusted is read once, here. That one reading judges the
        // bundle asked for and every bundle pinned below it, and it is held
        // until the last of them is judged: trust cannot change between two
        // bundles of one start. It is let go before anything is loaded.
        let trust = self.signature_verifier.read().await;
        let (mut admitted, accepted) = self
            .admit_closure_member(data_dir, &asked, &trust, &mut left, &mut after_walk)
            .await?;
        // What may sit below the bundle asked for follows from what it is. A
        // program pins programs. Content pins exactly one bundle, its
        // viewer, which must be a page. A page is reached through the
        // content that pins it and is not started by its own CID.
        let below_root = match (admitted.kind, admitted.pins.len()) {
            (BundleKind::Program, _) => BundleKind::Program,
            (BundleKind::Content, 1) => BundleKind::Page,
            (BundleKind::Content, pins) => return Err(BundleRefusal::ContentRequiresInvalid(pins)),
            (BundleKind::Page, _) => {
                return Err(bundle_admission::misplaced(BundleKind::Page, None))
            }
        };
        // The bundles it pins, and the ones those pin, in the manifests'
        // order and depth first: each is held to the checks just made, then
        // to its requirement's name and to the kind its place allows. The
        // flag marks the one program a content's page pins: its core.
        let below = |depth: usize, kind: BundleKind, core: bool, pins: Vec<(String, String)>| {
            let pins = pins.into_iter().rev();
            pins.map(move |(name, pin)| (depth + 1, kind, core, name, pin))
        };
        let pins = std::mem::take(&mut admitted.pins);
        // Every bundle admitted so far, by its CID: the name it carries, the
        // deepest place a pin has reached it at, and its own pins. The
        // bundle asked for is kept with its pins like any other: a cycle of
        // pins back to it cannot be built, and if one were, the measuring
        // would go round until the depth limit refused it.
        let root = (admitted.manifest.name.clone(), 1, pins.clone());
        let mut seen = HashMap::from([(asked.to_string(), root)]);
        let mut pending: Vec<_> = below(1, below_root, false, pins).collect();
        let mut members = 1;
        // What starts: the program asked for or, under content, the core.
        let mut starts = (admitted.kind == BundleKind::Program).then_some(admitted);
        while let Some((depth, expected, core, name, pin)) = pending.pop() {
            let refused = |refusal| BundleRefusal::Requirement {
                name: name.clone(),
                refusal: Box::new(refusal),
            };
            // No pin sits below the depth limit, whatever it pins: also a
            // pin on a bundle this start has already admitted higher up.
            if depth > bundle_admission::CLOSURE_MAX_DEPTH {
                return Err(refused(BundleRefusal::ClosureTooDeep));
            }
            let Ok(pinned) = pin.parse::<LabCid>() else {
                return Err(refused(BundleRefusal::CidFormInvalid(pin)));
            };
            // A bundle reached a second time, through another pin, was
            // admitted on its first reach. Its name must be this
            // requirement's too. It is not walked or counted again. Reached
            // deeper than before, its own pins sit deeper too: they are
            // measured again from here, out of memory, so that the depth
            // limit does not turn on which pin the walk met first. Its kind
            // needs no second look: content and its page could be reached
            // again only by a cycle of pins, which then starts nothing, so
            // what is reached twice is a program under a program, and what
            // it pins are programs.
            if let Some((carried, deepest, pins)) = seen.get_mut(&pinned.to_string()) {
                if *carried != name {
                    return Err(refused(BundleRefusal::RequirementMismatch(carried.clone())));
                }
                if depth > *deepest {
                    *deepest = depth;
                    pending.extend(below(depth, BundleKind::Program, false, pins.clone()));
                }
                continue;
            }
            members += 1;
            if members > bundle_admission::CLOSURE_MAX_MEMBERS {
                return Err(refused(BundleRefusal::ClosureTooMany));
            }
            let (mut member, _) = self
                .admit_closure_member(data_dir, &pinned, &trust, &mut left, &mut after_walk)
                .await
                .map_err(refused)?;
            if member.manifest.name != name {
                return Err(refused(BundleRefusal::RequirementMismatch(
                    member.manifest.name,
                )));
            }
            if member.kind != expected {
                let found = member.kind;
                return Err(refused(match core {
                    true => BundleRefusal::ViewerCoreInvalid(format!(
                        "the viewer pins {}, not a program",
                        bundle_admission::kind_word(found)
                    )),
                    false => bundle_admission::misplaced(found, Some(expected)),
                }));
            }
            // A page pins exactly one bundle, its program. Whatever a
            // program pins is a program.
            let pins = std::mem::take(&mut member.pins);
            let page = member.kind == BundleKind::Page;
            if page && pins.len() != 1 {
                return Err(refused(BundleRefusal::ViewerCoreInvalid(format!(
                    "the viewer pins {} bundles, not its one program",
                    pins.len()
                ))));
            }
            let known = (member.manifest.name.clone(), depth, pins.clone());
            seen.insert(pinned.to_string(), known);
            pending.extend(below(depth, BundleKind::Program, page, pins));
            if core {
                starts = Some(member);
            }
        }
        drop(trust);

        let failed = |error: ElastosError| BundleRefusal::StartFailed(error.to_string());
        let Some(component) = self.component_provider.clone() else {
            return Err(BundleRefusal::StartFailed(
                "No component compute provider is configured".to_string(),
            ));
        };
        // The seal follows the asks. A capsule whose manifest asks for
        // nothing is loaded sealed: the provider refuses its calls to the
        // bridge itself, so no handler sees one, whoever installed it. One
        // with asks is loaded unsealed, because it must be able to ask. Its
        // ceiling is filled where every capsule's is, by the shared end
        // below from the one bounds function; for a manifest this start
        // admits that is the asks and nothing else, because `asks` is the
        // one field on the key list that function reads.
        let Some(starts) = starts else {
            return Err(BundleRefusal::ViewerCoreInvalid(
                "no program was found under the viewer".to_string(),
            ));
        };
        let (bytes, manifest) = (starts.component, starts.manifest);
        let loaded = match manifest.asks.is_empty() {
            true => component.load_admitted_sealed(bytes, manifest).await,
            false => component.load_admitted(bytes, manifest).await,
        };
        let mut handle = loaded.map_err(failed)?;
        self.start_loaded(component, &mut handle, args, principal_id)
            .await
            .map_err(failed)?;
        Ok((handle, accepted))
    }

    /// The checks every bundle of a start by CID passes, the one asked for
    /// and each pinned one alike, in this order: the store has a slot for
    /// `cid`; one walk of it, inside what is `left` of the closure's budget;
    /// the files recompute to `cid`; the signature beside it is accepted
    /// under `trust`, the start's one reading of who is trusted; and only
    /// then this start judges its manifest and its component's imports.
    /// What the walk took in comes off `left`.
    ///
    /// The walk is not blind to the manifest: to name a bundle it parses
    /// and validates `capsule.json` with the Runtime's reader, before the
    /// CID and the signature are known to be right, and refuses what that
    /// reader refuses. It keeps the name, the role and the type from it and
    /// decides nothing else by it. The manifest that can start, and the
    /// pins that are followed, come from the judgement after the signature.
    async fn admit_closure_member(
        &self,
        data_dir: &Path,
        asked: &LabCid,
        trust: &SignatureVerifier,
        left: &mut Budget,
        after_walk: &mut impl FnMut(&LabCid),
    ) -> std::result::Result<(AdmittedBundle, AcceptedSignature), BundleRefusal> {
        let slot = bundle_admission::bundle_slot(data_dir, asked);
        match std::fs::symlink_metadata(&slot) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BundleRefusal::Missing(asked.to_string()));
            }
            Err(error) => {
                return Err(BundleRefusal::Store(format!(
                    "could not look at the slot for {asked}: {error}"
                )));
            }
        }
        // The one walk of the slot. The manifest and the component below
        // come from this value; the slot is not read again.
        let bundle = checked_bundle_within(&slot, *left).map_err(bundle_admission::walk_refusal)?;
        after_walk(asked);
        let files = bundle.entries();
        let bytes: u64 = files.iter().map(|file| file.content.len() as u64).sum();
        left.max_entries = left.max_entries.saturating_sub(files.len());
        left.max_total_bytes = left.max_total_bytes.saturating_sub(bytes);
        if bundle.cid() != *asked {
            return Err(BundleRefusal::CidMismatch {
                asked: asked.to_string(),
                computed: bundle.cid().to_string(),
            });
        }
        let signature = bundle_admission::bundle_signature_path(data_dir, asked);
        let accepted = bundle_admission::check_bundle_signature(&signature, asked, trust)?;
        let admitted = bundle_admission::admit_bundle_manifest(&bundle)?;
        if admitted.kind == BundleKind::Program {
            crate::component::validate_component_imports(&admitted.component)
                .map_err(BundleRefusal::NotAComponent)?;
        }
        Ok((admitted, accepted))
    }

    /// Test only: whether who is trusted could be replaced at this moment.
    /// It cannot while a start by CID holds its one reading.
    #[cfg(test)]
    pub(crate) fn trust_can_change_now(&self) -> bool {
        self.signature_verifier.try_write().is_ok()
    }

    /// Test only: the ceiling the bridge holds the capsule `id` to right now,
    /// each entry as it prints.
    #[cfg(test)]
    pub(crate) fn ceiling_of(&self, id: &str) -> Option<Vec<String>> {
        let ceilings = self.bridge_manifest_capabilities.read().unwrap();
        let ceiling = ceilings.get(id);
        ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect())
    }

    /// The end of every start, and the one place in this file that fills a
    /// capsule's ceiling: from the one bounds function, for a start from a
    /// folder and for a start by CID alike. While `provider` starts the
    /// loaded capsule, that ceiling is what the bridge holds it to and, for a
    /// component, `principal_id` is who it runs for; `args` go on its handle
    /// first. Ceiling and principal are taken away again when the start
    /// returns, well or badly.
    async fn start_loaded(
        &self,
        provider: Arc<dyn ComputeProvider>,
        handle: &mut CapsuleHandle,
        args: Vec<String>,
        principal_id: Option<String>,
    ) -> Result<()> {
        if let Ok(mut bounds) = self.bridge_manifest_capabilities.write() {
            bounds.insert(
                handle.id.0.clone(),
                handle.manifest.resource_authority_bounds(),
            );
        }
        if handle.manifest.is_component_capsule() {
            if let Some(ref component) = self.component_provider {
                component
                    .set_bridge_principal(&handle.id, principal_id)
                    .await;
            }
        }

        // Set args on handle before starting
        handle.args = args;

        // Start capsule
        let start = provider.start(handle).await;
        if handle.manifest.is_component_capsule() {
            if let Some(ref component) = self.component_provider {
                component.clear_bridge_principal(&handle.id).await;
            }
        }
        if let Ok(mut bounds) = self.bridge_manifest_capabilities.write() {
            bounds.remove(&handle.id.0);
        }
        start
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
        admitted: Option<&[u8]>,
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

        if verifier.trusted_key_count() == 0 {
            return Err(ElastosError::InvalidManifest(
                "Capsule signature verification has no trusted keys configured".into(),
            ));
        }

        // Hash the entrypoint: the bytes already read for a component, the file otherwise.
        let content_hash = match admitted {
            Some(bytes) => hash_content(bytes),
            None => {
                let entrypoint_path = path.join(&manifest.entrypoint);
                hash_content(&tokio::fs::read(&entrypoint_path).await.map_err(|e| {
                    ElastosError::InvalidManifest(format!(
                        "Failed to read entrypoint {}: {}",
                        manifest.entrypoint, e
                    ))
                })?)
            }
        };

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

    /// The map the launch entry fills: capsule id to ceiling.
    type Ceilings = Arc<StdRwLock<HashMap<String, Vec<AuthorityBound>>>>;

    /// Records, when a capsule starts, the ceiling the launch entry filled for it.
    #[derive(Default)]
    struct CeilingReadingProvider {
        ceilings: std::sync::OnceLock<Ceilings>,
        seen: std::sync::Mutex<Vec<Option<Vec<String>>>>,
    }

    #[async_trait]
    impl ComputeProvider for CeilingReadingProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("ceiling-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
            let ceilings = self.ceilings.get().unwrap().read().unwrap();
            let ceiling = ceilings.get(&handle.id.0);
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            self.seen.lock().unwrap().push(ceiling);
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

    /// The launch entry fills a capsule's ceiling from the bounds function: a
    /// capability is its ceiling, for any action (the control), and a
    /// manifest whose only authority field is asks is started under those
    /// asks, each with its actions.
    #[tokio::test]
    async fn the_launch_entry_starts_a_manifest_with_asks_under_its_asks() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let provider = Arc::new(CeilingReadingProvider::default());
        let runtime = Runtime::new(storage, provider.clone());
        assert!(provider
            .ceilings
            .set(runtime.bridge_manifest_capabilities.clone())
            .is_ok());
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = temp_dir.path().join("asks-launch");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        let mut with_capability = unsigned_manifest();
        with_capability.capsule_type = CapsuleType::MicroVM;
        with_capability.entrypoint = "rootfs.ext4".to_string();
        let mut with_asks = with_capability.clone();
        with_capability.capabilities = vec!["elastos://did/*".to_string()];
        with_asks.asks = vec![elastos_common::ManifestAsk {
            resource: "elastos://did/*".to_string(),
            actions: vec![elastos_common::AskAction::Read],
        }];
        for manifest in [with_capability, with_asks] {
            std::fs::write(
                dir.join("capsule.json"),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            runtime.run_local(&dir, Vec::new()).await.unwrap();
        }
        assert_eq!(
            *provider.seen.lock().unwrap(),
            vec![
                Some(vec!["elastos://did/*".to_string()]),
                Some(vec!["elastos://did/* [read]".to_string()])
            ]
        );
    }

    /// A manifest whose requirement carries a `cid`: a pin. Only
    /// `PinnedManifest` reads one; every start from a folder parses the
    /// ordinary manifest type, which refuses the key.
    pub(crate) const PINNED_MANIFEST: &str = r#"{"schema":"elastos.capsule/v1","name":"pinned-fixture","version":"0.1.0","role":"app","type":"microvm","entrypoint":"rootfs.ext4","requires":[{"name":"viewer","kind":"capsule","cid":"bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy"}]}"#;

    /// The same manifest with the pin taken out: the control of each row.
    pub(crate) fn unpinned_manifest() -> String {
        let pin = r#","cid":"bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy""#;
        assert_eq!(PINNED_MANIFEST.matches(pin).count(), 1);
        PINNED_MANIFEST.replace(pin, "")
    }

    /// Writes a capsule folder holding `manifest` and its entrypoint file.
    pub(crate) fn write_fixture_capsule(parent: &Path, manifest: &str) -> PathBuf {
        let dir = parent.join("pinned-fixture");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        std::fs::write(dir.join("capsule.json"), manifest).unwrap();
        dir
    }

    /// The launch entry stops at its own manifest parse for a pinned
    /// manifest, before a compute provider loads anything. The same manifest
    /// without the pin is loaded, so the pin is what stops it.
    #[tokio::test]
    async fn the_launch_entry_stops_at_its_manifest_parse_for_a_pinned_requirement() {
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
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = write_fixture_capsule(temp_dir.path(), PINNED_MANIFEST);
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        let expected = "Invalid manifest: Failed to parse capsule.json: unknown field `cid`";
        assert!(error.to_string().starts_with(expected), "{error}");
        assert_eq!(loads.load(Ordering::SeqCst), 0);

        write_fixture_capsule(temp_dir.path(), &unpinned_manifest());
        runtime.run_local(&dir, Vec::new()).await.unwrap();
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    /// What a provider saw when it was asked to start a capsule: the ceiling
    /// recorded for it, and the arguments on its handle.
    type SeenAtStart = (Option<Vec<String>>, Vec<String>);

    /// Records, at each start, the ceiling the launch entry filled for the
    /// capsule and the arguments on its handle; refuses the start when told to.
    #[derive(Default)]
    struct TailRecordingProvider {
        ceilings: std::sync::OnceLock<Ceilings>,
        starts: std::sync::Mutex<Vec<SeenAtStart>>,
        refuse: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl ComputeProvider for TailRecordingProvider {
        async fn load(&self, _path: &Path, manifest: CapsuleManifest) -> Result<CapsuleHandle> {
            Ok(CapsuleHandle {
                id: CapsuleId::new("tail-capsule"),
                manifest,
                args: Vec::new(),
            })
        }

        async fn start(&self, handle: &CapsuleHandle) -> Result<()> {
            let ceilings = self.ceilings.get().unwrap().read().unwrap();
            let ceiling = ceilings.get(&handle.id.0);
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            self.starts
                .lock()
                .unwrap()
                .push((ceiling, handle.args.clone()));
            if self.refuse.load(Ordering::SeqCst) {
                return Err(ElastosError::Compute("refused by the test".to_string()));
            }
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

    /// The end of the folder start, asserted where it is called: while the
    /// provider starts the capsule, the ceiling recorded for it is its
    /// manifest's, and its handle carries the caller's arguments; when the
    /// start has ended, well or badly, no ceiling is left for it. Written
    /// before that end is shared with the start by CID, so that the move
    /// keeps each of these.
    #[tokio::test]
    async fn the_folder_start_records_the_ceiling_hands_over_the_args_and_clears_the_ceiling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let provider = Arc::new(TailRecordingProvider::default());
        let runtime = Runtime::new(storage, provider.clone());
        assert!(provider
            .ceilings
            .set(runtime.bridge_manifest_capabilities.clone())
            .is_ok());
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let dir = temp_dir.path().join("tail");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rootfs.ext4"), b"vm image bytes").unwrap();
        let mut manifest = unsigned_manifest();
        manifest.capsule_type = CapsuleType::MicroVM;
        manifest.entrypoint = "rootfs.ext4".to_string();
        manifest.capabilities = vec!["elastos://did/*".to_string()];
        manifest.permissions.storage = vec!["localhost://Users/self/Documents/*".to_string()];
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let ceiling = vec![
            "elastos://did/*".to_string(),
            "localhost://Users/self/Documents/*".to_string(),
        ];
        let args = vec!["one".to_string(), "two".to_string()];
        let none_left = || {
            runtime
                .bridge_manifest_capabilities
                .read()
                .unwrap()
                .is_empty()
        };

        let handle = runtime.run_local(&dir, args.clone()).await.unwrap();
        assert_eq!(handle.args, args);
        assert_eq!(handle.id.0, "tail-capsule");
        assert_eq!(
            *provider.starts.lock().unwrap(),
            vec![(Some(ceiling.clone()), args.clone())]
        );
        assert!(
            none_left(),
            "no ceiling is left after a start that ended well"
        );

        provider.refuse.store(true, Ordering::SeqCst);
        let error = runtime.run_local(&dir, Vec::new()).await.unwrap_err();
        assert_eq!(error.to_string(), "Compute error: refused by the test");
        assert_eq!(
            *provider.starts.lock().unwrap(),
            vec![(Some(ceiling.clone()), args), (Some(ceiling), Vec::new())]
        );
        assert!(none_left(), "no ceiling is left after a start that failed");
    }

    /// The same for a component, through the real component provider. The
    /// fixture component asks the Runtime who it runs for and goes on only
    /// for its own person; then it calls the bridge. So: with that person
    /// given, its call reaches the bridge with that principal and under the
    /// ceiling of its manifest; with no person given, it ends before any
    /// call. No ceiling is left either time. The bridge here answers with a
    /// refusal, so nothing is granted and no provider is asked.
    #[tokio::test]
    async fn the_folder_start_of_a_component_gives_the_bridge_its_principal_and_ceiling() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        type Call = (String, Option<String>, Option<Vec<String>>);
        let calls: Arc<std::sync::Mutex<Vec<Call>>> = Arc::default();
        let seen = calls.clone();
        let ceilings = runtime.bridge_manifest_capabilities.clone();
        runtime.set_bridge_hostcall(Arc::new(move |_line, capsule_id, principal_id| {
            let ceiling = ceilings.read().unwrap().get(capsule_id).cloned();
            let ceiling = ceiling.map(|ceiling| ceiling.iter().map(ToString::to_string).collect());
            seen.lock().unwrap().push((
                capsule_id.to_string(),
                principal_id.map(ToOwned::to_owned),
                ceiling,
            ));
            Err("refused by the test".to_string())
        }));
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/components/bus-v1");
        let person = "person:local:bus-conformance";

        let ended = runtime
            .run_local_with_principal(&fixture, Vec::new(), Some(person.to_string()))
            .await;

        let none_left = || {
            runtime
                .bridge_manifest_capabilities
                .read()
                .unwrap()
                .is_empty()
        };
        let made = calls.lock().unwrap().clone();
        assert_eq!(made.len(), 1, "one call, refused: {made:?}");
        for (capsule_id, principal_id, ceiling) in made.iter() {
            assert!(capsule_id.starts_with("component-"), "{capsule_id}");
            assert_eq!(principal_id.as_deref(), Some(person));
            assert_eq!(
                ceiling.as_deref(),
                Some(&["elastos://test/bus/probe".to_string()][..])
            );
        }
        assert!(none_left(), "no ceiling is left after the component ended");
        let error = ended.expect_err("the fixture ends in an error when its call is refused");
        assert_eq!(
            error.to_string(),
            "Compute error: Component capsule denied: BusError::Internal(\"refused by the test\")"
        );

        let error = runtime
            .run_local_with_principal(&fixture, Vec::new(), None)
            .await
            .expect_err("the fixture does not go on without its person");
        assert_eq!(
            error.to_string(),
            "Compute error: Component capsule denied: BusError::Denied(\"Runtime did not bind the conformance principal\")"
        );
        assert_eq!(calls.lock().unwrap().len(), 1, "no call without the person");
        assert!(none_left(), "no ceiling is left after that start either");
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
            asks: Vec::new(),
            signature: None,
        }
    }

    pub(crate) fn component_with_extra_import() -> Vec<u8> {
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
                .verify_capsule_signature(&unsigned_manifest(), temp_dir.path(), None)
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
                .verify_capsule_signature(&manifest, &release_dir, None)
                .await
                .unwrap(),
            Signer::InstalledRelease
        );
        let error = runtime
            .verify_capsule_signature(&manifest, &local_dir, None)
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
            .verify_capsule_signature(&declared, &release_dir, None)
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
            .verify_capsule_signature(&signed_by(71), &local_dir, None)
            .await
            .unwrap();
        let error = runtime
            .verify_capsule_signature(&signed_by(9), &local_dir, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("verification failed"), "{error}");

        // A release capsule whose CID receipt no longer matches is refused too.
        std::fs::write(release_dir.join(".elastos-cid"), "bafkreiother").unwrap();
        assert!(runtime
            .verify_capsule_signature(&manifest, &release_dir, None)
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
            .verify_capsule_signature(&manifest, &dir, None)
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
                    .verify_capsule_signature(&capsule, &dir, None)
                    .await
                    .unwrap(),
                Signer::UnsignedDev
            );
        }
    }

    /// For a component the signature is checked over the bytes the Runtime
    /// already read, whatever the file holds by then.
    #[tokio::test]
    async fn a_signature_is_checked_over_the_admitted_bytes_not_the_file() {
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
        let (signed, other): (&[u8], &[u8]) = (b"the signed bytes", b"replaced after the read");
        let mut manifest = unsigned_manifest();
        manifest.entrypoint = "main.wasm".to_string();
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(signed))
            .unwrap();

        // The file was replaced after the read: the signed bytes in hand still pass.
        std::fs::write(dir.join("main.wasm"), other).unwrap();
        runtime
            .verify_capsule_signature(&manifest, &dir, Some(signed))
            .await
            .expect("the signed bytes that were read pass");
        // The file still holds the signed bytes, but other bytes were read: refused.
        std::fs::write(dir.join("main.wasm"), signed).unwrap();
        let error = runtime
            .verify_capsule_signature(&manifest, &dir, Some(other))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("signature verification failed"),
            "{error}"
        );
    }

    /// A component with one empty `run`, as bytes.
    pub(crate) fn quiet_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
              (import "elastos:bus/types@1.0.0" (instance $types
                (type $error (variant
                  (case "denied" string) (case "not-found" string) (case "invalid" string)
                  (case "unavailable" string) (case "timeout" string) (case "internal" string)))
                (export "bus-error" (type (eq $error)))))
              (alias export $types "bus-error" (type $bus-error))
              (core module $m
                (memory (export "memory") 1)
                (func (export "run") (result i32) (i32.const 0)))
              (core instance $i (instantiate $m))
              (func $run (result (result (error $bus-error)))
                (canon lift (core func $i "run") (memory $i "memory")))
              (instance $lifecycle (export "run" (func $run)))
              (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#,
        )
        .expect("component text")
    }

    pub(crate) fn component_manifest_json(name: &str) -> String {
        format!(
            r#"{{
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": "{name}",
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
        )
    }

    /// The file is replaced right after the Runtime's one read of it (a test
    /// hook runs at that point). The capsule is signed and the Home enforces
    /// signatures, so the signature check, the import check and the compiler
    /// all take part: any of them reading the file again meets the
    /// replacement, and the launch fails.
    #[tokio::test]
    async fn a_component_file_replaced_after_it_was_read_runs_the_bytes_that_were_checked() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        let key = elastos_runtime::signature::SigningKey::from_bytes(&[71; 32]);
        runtime
            .configure_capsule_admission(
                temp_dir.path(),
                &[hex::encode(key.verifying_key().to_bytes())],
                false,
            )
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        let component = quiet_component();
        let mut manifest: CapsuleManifest =
            serde_json::from_str(&component_manifest_json("replaced-component")).unwrap();
        elastos_runtime::signature::sign_capsule(&key, &mut manifest, &hash_content(&component))
            .unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::to_string(&manifest).unwrap(),
        )
        .unwrap();
        let entrypoint = capsule_dir.join("app.component.wasm");
        std::fs::write(&entrypoint, &component).unwrap();

        let replacement: &[u8] = b"replaced after the check";
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        crate::component::AFTER_ENTRYPOINT_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |path| {
                counted.fetch_add(1, Ordering::SeqCst);
                std::fs::write(path, replacement).unwrap();
            }));
        });
        // The hook is taken away again however this test ends.
        struct ResetHook;
        impl Drop for ResetHook {
            fn drop(&mut self) {
                crate::component::AFTER_ENTRYPOINT_READ.with(|hook| *hook.borrow_mut() = None);
            }
        }
        let _reset = ResetHook;
        let launched = runtime
            .run_local_with_signer(&capsule_dir, Vec::new(), None)
            .await;

        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "one read of the entrypoint"
        );
        assert_eq!(std::fs::read(&entrypoint).unwrap(), replacement);
        let (_, signer) = launched.expect("the bytes that were checked are the bytes that run");
        let did = elastos_identity::encode_did_key(&key.verifying_key()).unwrap();
        assert_eq!(signer, Signer::Key { did });
    }

    /// A component file one byte over the cap is refused at launch, before the
    /// signature check, the import check or the compiler see it.
    #[tokio::test]
    async fn a_component_file_over_the_size_cap_is_refused_at_launch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let runtime = Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        );
        runtime
            .configure_capsule_admission(temp_dir.path(), &[], true)
            .await
            .unwrap();
        let capsule_dir = temp_dir.path().join("capsule");
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            component_manifest_json("oversized-component"),
        )
        .unwrap();
        let file = std::fs::File::create(capsule_dir.join("app.component.wasm")).unwrap();
        file.set_len(8 * 1024 * 1024 + 1).unwrap();

        let error = runtime
            .run_local_with_principal(&capsule_dir, Vec::new(), None)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Invalid manifest: failed to read component entrypoint app.component.wasm: \
             component file is larger than the 8388608 byte limit"
        );
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

    /// A capsule started by its CID is held to its asks by the real bridge.
    /// The bus fixture component asks the Runtime for a read grant on its
    /// probe resource, then reads it. Staged with a manifest that asks for
    /// exactly that, its request reaches the shell as a pending request: the
    /// ask itself granted nothing. Granted there, the read reaches the
    /// provider and the run ends well, and no ceiling is left behind. Staged
    /// with an ask on the same resource that lists only `write`, the bridge
    /// refuses the request for the read, in the sentence that names the
    /// action; no prompt is made and the provider sees nothing more.
    #[tokio::test]
    async fn a_capsule_started_by_cid_is_held_to_its_asks_by_the_real_bridge() {
        use crate::bundle_admission::tests::{key, signed};
        use crate::stage_cmd::{bundle_cid, stage_bundle};
        let temp_dir = tempfile::tempdir().unwrap();
        let data_dir = temp_dir.path().join("data");
        let storage = Arc::new(
            LocalFSProvider::new(temp_dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let publisher = key(71);
        let trusted = [hex::encode(publisher.verifying_key().to_bytes())];
        runtime
            .configure_capsule_admission(temp_dir.path(), &trusted, false)
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

        let component = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"),
        )
        .unwrap();
        let probe = "elastos://test/bus/probe";
        // Stage a bundle named `name` whose manifest asks for `actions` on the probe.
        let staged = |name: &'static str, actions: &'static [&'static str]| {
            let (runtime, data_dir, component) = (runtime.clone(), data_dir.clone(), &component);
            let folder = temp_dir.path().join("source").join(name);
            let signature = temp_dir.path().join(format!("{name}.sig.json"));
            let publisher = &publisher;
            async move {
                let mut manifest: serde_json::Value =
                    serde_json::from_str(&component_manifest_json(name)).unwrap();
                manifest["asks"] = serde_json::json!([{"resource": probe, "actions": actions}]);
                std::fs::create_dir_all(&folder).unwrap();
                std::fs::write(folder.join("capsule.json"), manifest.to_string()).unwrap();
                std::fs::write(folder.join("app.component.wasm"), component).unwrap();
                let cid = bundle_cid(&folder).unwrap();
                std::fs::write(&signature, signed(&cid, publisher)).unwrap();
                stage_bundle(&runtime, &data_dir, &folder, &signature)
                    .await
                    .unwrap();
                cid
            }
        };
        let start = |cid: String| {
            let (runtime, data_dir) = (runtime.clone(), data_dir.clone());
            tokio::spawn(async move {
                let person = Some("person:local:bus-conformance".to_string());
                let ran = runtime.run_by_bundle(&data_dir, &cid, Vec::new(), person);
                ran.await.map(|(handle, _)| handle.manifest.name)
            })
        };

        // Inside the asks.
        let launch = start(staged("asks-read", &["read"]).await);
        let pending = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(request) = pending_store.list_pending().await.into_iter().next() {
                    break request;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a request inside the asks reaches the shell");
        assert_eq!(pending.resource.as_str(), probe);
        assert_eq!(pending.action, elastos_runtime::capability::Action::Read);
        assert!(provider.requests.lock().await.is_empty(), "no grant yet");
        let capsule_id = pending.session_id.as_str().to_string();
        assert_eq!(
            runtime.ceiling_of(&capsule_id),
            Some(vec![format!("{probe} [read]")]),
            "while it runs, its ceiling is its asks"
        );
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
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), launch)
            .await
            .expect("the run ends after the grant")
            .expect("the launch task does not panic");
        assert_eq!(ended.unwrap(), "asks-read");
        assert_eq!(provider.requests.lock().await.len(), 1);
        assert_eq!(runtime.ceiling_of(&capsule_id), None, "none left after");

        // Beyond the asks: the same resource, but the action is not listed.
        let refused = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            start(staged("asks-write", &["write"]).await),
        )
        .await
        .expect("a refused run ends at once")
        .expect("the launch task does not panic")
        .expect_err("the request for the read is refused");
        assert_eq!(refused.code(), "bundle_start_failed");
        let sentence = format!("capsule manifest does not declare authority to read {probe}");
        assert!(refused.to_string().contains(&sentence), "{refused}");
        assert!(
            pending_store.list_pending().await.is_empty(),
            "no prompt was made"
        );
        assert_eq!(provider.requests.lock().await.len(), 1, "nothing more");
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
