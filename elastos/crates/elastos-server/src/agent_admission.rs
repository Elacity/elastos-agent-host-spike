//! The checks made when an agent is created or launched. Nothing here starts an
//! agent itself.
//!
//! - Agents stay on their owner's Home. A Runtime whose sign-in store is not
//!   its own data folder is a child of another Runtime and creates none.
//! - The Agent Host an agent is created for is installed from this Home's
//!   signed release, at the path that release records, and its manifest is
//!   signed by the one key that signed that release. An unsigned package is
//!   refused whatever `dev_mode` says, and so is one the release records but
//!   no key signed. Other configured publisher keys, and keys trusted only by
//!   this Home's own configuration, are not asked.
//! - The Runtime names the host's bytes itself: one walk, the same one staging
//!   uses, gives both the CID creation stores and the bytes a later launch must
//!   present. No receipt file written by whoever prepares a directory decides
//!   that identity.

use std::path::Path;

use elastos_bundle_identity::{checked_bundle_within, MANIFEST_FILE};
use elastos_common::CapsuleManifest;
use elastos_runtime::signature::{hash_content, SignatureVerifier};

use crate::agents::Refused;
use crate::auth::{AgentHostPackage, PrincipalKind};
use crate::bundle_admission::BUNDLE_WALK_BUDGET;

/// The refusal a child Runtime gives.
pub(crate) const NOT_THE_HOME: &str =
    "agents stay on their owner's Home: this Runtime's sign-in store is not its own";

/// An Agent Host package that passed `verify_agent_host`: the package name
/// and the registry CID of its entry in the signed components record.
pub(crate) struct VerifiedAgentHost(AgentHostPackage);

impl VerifiedAgentHost {
    pub(crate) fn package(&self) -> &AgentHostPackage {
        &self.0
    }

    /// A package no check has passed, for tests of what follows the check.
    #[cfg(test)]
    pub(crate) fn unchecked_for_test(name: &str, registry_cid: &str, bundle_cid: &str) -> Self {
        Self(AgentHostPackage {
            name: name.to_string(),
            registry_cid: registry_cid.to_string(),
            bundle_cid: bundle_cid.to_string(),
        })
    }
}

/// Refuses unless this Runtime's sign-in store is its own data folder.
pub(crate) fn require_home_runtime(data_dir: &Path, sign_in_store: &Path) -> anyhow::Result<()> {
    if sign_in_store != data_dir {
        return Err(Refused(NOT_THE_HOME.to_string()).into());
    }
    Ok(())
}

/// What one launch was admitted as: the stored agent's principal id and the
/// exact manifest and entrypoint bytes the Runtime walked. The bridge runs as
/// `actor`. Its root comes from the one root rule at the bridge, and its owner
/// and its storage protection are read again from the stored record, so neither
/// is copied here. The loader compiles `entrypoint` and parses `manifest` from
/// these bytes; it reads neither back from the folder.
#[derive(Debug)]
pub(crate) struct AdmissionContext {
    pub(crate) actor: String,
    pub(crate) manifest: CapsuleManifest,
    pub(crate) entrypoint: Vec<u8>,
}

/// The refusal a launch gives when it names an agent and no launcher is.
pub(crate) const NO_LAUNCHER: &str = "an agent launch needs its owner's launch grant";

/// The refusal a launch gives when the capsule it would load is not the Agent
/// Host package the agent was created for.
pub(crate) const NOT_THE_STORED_HOST: &str =
    "this capsule is not the Agent Host this agent was created for";

/// The refusal a launch gives when the stored agent has no byte identity. A
/// record written before the Runtime named the host's bytes carries no CID, and
/// it is not re-derived from a receipt or from the release record: the launch
/// fails closed.
pub(crate) const NO_STORED_BYTES: &str =
    "this agent's stored Agent Host has no recorded byte identity, so no launch can name it";

/// The refusal a launch gives for a package the Runtime cannot compile from the
/// bytes it walked.
pub(crate) const NOT_A_COMPONENT: &str =
    "an agent launch runs only a component capsule the Runtime can name";

/// One walk of a launch directory: its byte CID, the manifest that walk read,
/// and the entrypoint bytes it read. The route authorizes the launch grant from
/// this manifest's name, admission compares this CID with the stored host, and
/// the loader compiles these bytes. Nothing is read from the folder again.
#[derive(Debug)]
pub(crate) struct WalkedLaunch {
    pub(crate) bundle_cid: String,
    pub(crate) manifest: CapsuleManifest,
    pub(crate) entrypoint: Vec<u8>,
}

/// The refusal a launch gives for a capsule whose manifest declares no agent.
pub(crate) const NOT_AN_AGENT: &str =
    "this capsule does not declare an agent, so no stored agent runs it";

/// Walk `capsule_dir` once, under the same limits staging uses, and return its
/// CID, the manifest that walk read, and its entrypoint bytes. The caller
/// carries this one value through the grant check, admission, and the load;
/// nothing reads the folder again.
pub(crate) fn walk_launch(capsule_dir: &Path) -> anyhow::Result<WalkedLaunch> {
    let bundle = checked_bundle_within(capsule_dir, BUNDLE_WALK_BUDGET)
        .map_err(|refusal| anyhow::anyhow!("walk the launching capsule: {refusal}"))?;
    let manifest_bytes = bundle
        .entry(MANIFEST_FILE)
        .ok_or_else(|| anyhow::anyhow!("the launching capsule has no manifest"))?;
    let manifest: CapsuleManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|err| anyhow::anyhow!("parse the launching capsule's manifest: {err}"))?;
    let entrypoint = bundle
        .entry(&manifest.entrypoint)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the launching capsule has no entrypoint file '{}'",
                manifest.entrypoint
            )
        })?
        .to_vec();
    Ok(WalkedLaunch {
        bundle_cid: bundle.cid().to_string(),
        manifest,
        entrypoint,
    })
}

/// Admits a launch that names a stored agent, and leaves every other launch
/// exactly as it was. `None` means no agent was named. Otherwise this Runtime
/// holds its own sign-in store, the launcher is a stored person, the named id
/// is that person's stored agent, the walked capsule is the Agent Host bytes
/// the agent's storage records, and the agent's stored protection opens with
/// that person's key. A launch that cannot meet any of that is refused here,
/// before any provider starts and before any principal is bound.
///
/// `walked` is the one value `walk_launch` produced; the grant check already
/// read this manifest's name, and the loader compiles its entrypoint. Admission
/// opens no file in the launching folder.
pub(crate) fn admit_launch(
    data_dir: &Path,
    sign_in_store: &Path,
    launcher: Option<&str>,
    agent: Option<&str>,
    walked: WalkedLaunch,
) -> anyhow::Result<Option<AdmissionContext>> {
    let Some(agent_id) = agent else {
        return Ok(None);
    };
    crate::agents::require_build()?;
    require_home_runtime(data_dir, sign_in_store)?;
    let Some(launcher) = launcher else {
        return Err(Refused(NO_LAUNCHER.to_string()).into());
    };
    let stored = crate::agents::stored_agent(data_dir, launcher, agent_id)?;
    // The Runtime names the bytes it would run. The stored agent carries the
    // Agent Host package it was created for, with the CID the walk of its
    // installed files gave; this launch's walk must give the same CID and the
    // same manifest name. No receipt file in the launching folder is read.
    let WalkedLaunch {
        bundle_cid,
        manifest,
        entrypoint,
    } = walked;
    if manifest.agent.is_none() {
        return Err(Refused(NOT_AN_AGENT.to_string()).into());
    }
    if !manifest.is_component_capsule() {
        return Err(Refused(NOT_A_COMPONENT.to_string()).into());
    }
    let stored_host = stored.record.agent_host_package.as_ref();
    let Some(host) = stored_host else {
        return Err(Refused(NOT_THE_STORED_HOST.to_string()).into());
    };
    // A record from before the Runtime named host bytes carries an empty CID.
    // It is refused by name rather than re-derived from a file or the release.
    if host.bundle_cid.is_empty() {
        return Err(Refused(NO_STORED_BYTES.to_string()).into());
    }
    if host.name != manifest.name || host.bundle_cid != bundle_cid {
        return Err(Refused(NOT_THE_STORED_HOST.to_string()).into());
    }
    // The root is derived from the id, never read from a field of the record
    // on its own, and the record must hold the root its own id owns.
    let root = crate::auth::principal_kind_localhost_root(agent_id, PrincipalKind::Agent);
    if stored.record.localhost_root != root {
        return Err(Refused("agent record's root is not the root its id owns".to_string()).into());
    }
    let _key = zeroize::Zeroizing::new(crate::auth::open_agent_root_data_key(
        data_dir,
        &stored.protection,
    )?);
    Ok(Some(AdmissionContext {
        actor: agent_id.to_string(),
        manifest,
        entrypoint,
    }))
}

/// The refusal a launch gives when an agent's principal reaches it without an
/// admission context.
pub(crate) const UNADMITTED_AGENT_PRINCIPAL: &str =
    "a stored agent's principal reaches only a launch that admitted it";

/// Refuses an agent's own principal on any entrance that did not admit it. An
/// agent's id reaches a bridge principal only through `admit_launch`, so every
/// other entrance closes rather than guesses. A build without the feature
/// changes nothing, and a launch with no principal passes.
pub(crate) fn refuse_unadmitted_agent_principal(principal_id: Option<&str>) -> anyhow::Result<()> {
    if !crate::agents::build_allows() {
        return Ok(());
    }
    let Some(id) = principal_id.filter(|id| crate::auth::validate_agent_id(id).is_ok()) else {
        return Ok(());
    };
    anyhow::bail!("{UNADMITTED_AGENT_PRINCIPAL}: {id}")
}

/// Checks the Agent Host named by a create request. See the module rules.
pub(crate) fn verify_agent_host(
    data_dir: &Path,
    agent_host: &str,
) -> anyhow::Result<VerifiedAgentHost> {
    let refuse =
        |why: &str| anyhow::Error::new(Refused(format!("agent host '{agent_host}' {why}")));
    let Some(source) = crate::setup::installed_release_source(data_dir)? else {
        return Err(refuse("is not from an installed signed release"));
    };
    let binary = std::fs::canonicalize(&source.install_path)?;
    // The release envelope and its components, read and verified against the
    // configured publisher keys. Its `signer_did` is the key that verified it.
    let (release, components) =
        crate::installed_release::read_signed_release(data_dir, &binary, &source, false)?;
    let release: serde_json::Value = serde_json::from_slice(&release)?;
    let Some(release_signer) = release["signer_did"].as_str() else {
        return Err(refuse("is from a release with no signer"));
    };
    let components: crate::setup::ComponentsManifest = serde_json::from_slice(&components)?;
    let (Some(component), Some(entry)) = (
        components.external.get(agent_host),
        components.capsules.get(agent_host),
    ) else {
        return Err(refuse("has no entry in the signed components record"));
    };
    let platform = crate::setup::detect_platform();
    let platform = crate::setup::resolve_platform_info(component, &platform);
    let Some(install_path) = crate::setup::resolve_install_path(component, platform) else {
        return Err(refuse(
            "has no install path in the signed components record",
        ));
    };
    let dir = data_dir.join(install_path);
    if let Err(error) = crate::setup::verify_installed_release_capsule(data_dir, agent_host, &dir) {
        return Err(refuse(&format!(
            "is not installed as its signed release records: {error:#}"
        )));
    }

    // One walk of the installed folder, the same walk staging uses, names the
    // bytes this agent runs: its CID, the manifest that walk read, and the
    // entrypoint bytes the signature check covers. No second read decides them.
    let bundle = checked_bundle_within(&dir, BUNDLE_WALK_BUDGET)
        .map_err(|refusal| refuse(&format!("is not a bundle the Runtime can name: {refusal}")))?;
    let Some(manifest_bytes) = bundle.entry(MANIFEST_FILE) else {
        return Err(refuse("has no manifest"));
    };
    let Ok(manifest) = serde_json::from_slice::<CapsuleManifest>(manifest_bytes) else {
        return Err(refuse("has a manifest that does not parse"));
    };
    let entrypoint = Path::new(&manifest.entrypoint);
    if manifest.name != agent_host
        || manifest.validate().is_err()
        || manifest.entrypoint.contains("..")
        || entrypoint.is_absolute()
    {
        return Err(refuse("has a manifest that is not valid for it"));
    }
    let mut verifier = SignatureVerifier::new();
    verifier.add_trusted_key(crate::crypto::decode_did_key(release_signer)?)?;
    let Some(content) = bundle.entry(&manifest.entrypoint) else {
        return Err(refuse("has no entrypoint file"));
    };
    let key_signed = manifest.signature.is_some()
        && verifier
            .verify_capsule(&manifest, &hash_content(content))
            .is_ok_and(|key| key.is_some());
    if !key_signed {
        return Err(refuse(
            "is not signed by the key that signed its installed release",
        ));
    }
    Ok(VerifiedAgentHost(AgentHostPackage {
        name: agent_host.to_string(),
        registry_cid: entry.cid.clone(),
        bundle_cid: bundle.cid().to_string(),
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::installed_release::tests::Fixture;

    pub(crate) const AGENT_HOST: &str = "agent-host";
    pub(crate) const AGENT_HOST_CID: &str = "bafkreiagenthost";
    const ENTRYPOINT: &[u8] = b"agent host entrypoint";

    /// How the Agent Host's manifest is signed in a fixture.
    #[derive(Clone, Copy)]
    pub(crate) enum Signed {
        /// By the fixture release's publisher key.
        ByPublisher,
        /// By a key the release does not name.
        ByStranger,
        /// Not at all: the release records the package and no key signed it.
        No,
    }

    /// An installed signed release whose components record lists the Agent
    /// Host, with the package installed at its recorded path.
    pub(crate) fn installed_agent_host(signed: Signed) -> Fixture {
        let mut home = Fixture::new();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1/capsule.json");
        let mut manifest: CapsuleManifest =
            serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
        manifest.name = AGENT_HOST.to_string();
        manifest.signature = None;
        let key = |value: u8| elastos_runtime::signature::SigningKey::from_bytes(&[value; 32]);
        let mut sign = |value: u8| {
            let hash = hash_content(ENTRYPOINT);
            elastos_runtime::signature::sign_capsule(&key(value), &mut manifest, &hash).unwrap()
        };
        match signed {
            // The fixture release is signed by key 71.
            Signed::ByPublisher => sign(71),
            Signed::ByStranger => sign(9),
            Signed::No => {}
        }
        let sha256 = "ab".repeat(32);
        std::fs::write(
            home.data.join("components.json"),
            serde_json::to_vec(&serde_json::json!({
                "external": {(AGENT_HOST): {
                    "install_path": format!("capsules/{AGENT_HOST}"),
                    "platforms": {(crate::setup::detect_platform()): {
                        "cid": AGENT_HOST_CID, "checksum": format!("sha256:{sha256}"),
                        "extract_path": format!("capsules/{AGENT_HOST}")
                    }}
                }},
                "capsules": {(AGENT_HOST): {"cid": AGENT_HOST_CID, "sha256": sha256}},
                "profiles": {}
            }))
            .unwrap(),
        )
        .unwrap();
        home.bind_components();
        let dir = home.data.join("capsules").join(AGENT_HOST);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("capsule.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        std::fs::write(dir.join(&manifest.entrypoint), ENTRYPOINT).unwrap();
        std::fs::write(dir.join(".elastos-cid"), AGENT_HOST_CID).unwrap();
        std::fs::write(dir.join(".elastos-artifact-sha256"), &sha256).unwrap();
        home
    }

    fn refusal(data_dir: &Path, agent_host: &str) -> String {
        match verify_agent_host(data_dir, agent_host) {
            Ok(_) => panic!("the agent host was admitted"),
            Err(error) => error
                .downcast_ref::<Refused>()
                .map(|refused| refused.0.clone())
                .unwrap_or_else(|| panic!("not a named refusal: {error:#}")),
        }
    }

    #[test]
    fn an_agent_host_installed_from_the_release_and_signed_by_its_publisher_is_admitted() {
        let home = installed_agent_host(Signed::ByPublisher);
        let host = verify_agent_host(&home.data, AGENT_HOST).unwrap();
        assert_eq!(host.package().name, AGENT_HOST);
        assert_eq!(host.package().registry_cid, AGENT_HOST_CID);
    }

    #[test]
    fn a_home_with_no_installed_signed_release_admits_no_agent_host() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            refusal(dir.path(), AGENT_HOST),
            "agent host 'agent-host' is not from an installed signed release"
        );
    }

    #[test]
    fn a_package_with_no_components_entry_is_refused() {
        let home = installed_agent_host(Signed::ByPublisher);
        assert_eq!(
            refusal(&home.data, "other-host"),
            "agent host 'other-host' has no entry in the signed components record"
        );
    }

    #[test]
    fn a_package_no_key_signed_is_refused_even_with_dev_mode_on() {
        let home = installed_agent_host(Signed::No);
        std::fs::write(home.data.join("config.toml"), "dev_mode = true\n").unwrap();
        // The release records this package and its receipts match.
        let dir = home.data.join("capsules").join(AGENT_HOST);
        crate::setup::verify_installed_release_capsule(&home.data, AGENT_HOST, &dir).unwrap();
        assert_eq!(
            refusal(&home.data, AGENT_HOST),
            "agent host 'agent-host' is not signed by the key that signed its installed release"
        );
    }

    #[test]
    fn a_package_signed_by_a_key_the_release_does_not_name_is_refused() {
        let home = installed_agent_host(Signed::ByStranger);
        assert_eq!(
            refusal(&home.data, AGENT_HOST),
            "agent host 'agent-host' is not signed by the key that signed its installed release"
        );
    }

    #[test]
    fn a_key_added_to_the_configuration_that_did_not_sign_the_release_is_refused() {
        let home = installed_agent_host(Signed::ByStranger);
        // Key 9 signed the Agent Host. It joins the configured publisher keys;
        // the installed release is still the one key 71 signed.
        let mut sources = crate::sources::load_trusted_sources(&home.data).unwrap();
        let stranger = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        sources.sources[0]
            .publisher_dids
            .push(crate::crypto::encode_signing_key_did(&stranger));
        crate::sources::save_trusted_sources(&home.data, &sources).unwrap();
        let dir = home.data.join("capsules").join(AGENT_HOST);
        crate::setup::verify_installed_release_capsule(&home.data, AGENT_HOST, &dir).unwrap();
        assert_eq!(
            refusal(&home.data, AGENT_HOST),
            "agent host 'agent-host' is not signed by the key that signed its installed release"
        );
    }

    #[test]
    fn a_package_whose_receipts_differ_from_the_release_is_refused() {
        let home = installed_agent_host(Signed::ByPublisher);
        let dir = home.data.join("capsules").join(AGENT_HOST);
        std::fs::write(dir.join(".elastos-cid"), "bafkreiother").unwrap();
        let reason = refusal(&home.data, AGENT_HOST);
        assert!(
            reason.starts_with(
                "agent host 'agent-host' is not installed as its signed release records:"
            ),
            "{reason}"
        );
    }

    #[test]
    fn only_a_runtime_on_its_own_sign_in_store_is_the_home() {
        let (home, parent) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        require_home_runtime(home.path(), home.path()).unwrap();
        let error = require_home_runtime(home.path(), parent.path()).unwrap_err();
        assert_eq!(error.to_string(), NOT_THE_HOME);
    }

    /// Row 5d at the one refusal every launch entrance shares: an agent's own
    /// principal is refused by name, and no other principal is touched.
    #[test]
    fn an_agents_principal_reaches_only_a_launch_that_admitted_it() {
        let agent = "agent:v2:0123456789abcdef0123456789abcdef";
        let refusal = |id: Option<&str>| {
            refuse_unadmitted_agent_principal(id)
                .err()
                .map(|err| err.to_string())
        };
        let expected = "a stored agent's principal reaches only a launch that admitted it: \
                        agent:v2:0123456789abcdef0123456789abcdef";
        if crate::agents::build_allows() {
            assert_eq!(refusal(Some(agent)).unwrap(), expected);
        } else {
            assert_eq!(
                refusal(Some(agent)),
                None,
                "a build without the feature refuses no principal"
            );
        }
        assert_eq!(refusal(Some("person:local:a5-owner")), None);
        assert_eq!(refusal(None), None);
    }
}
