//! The checks made when an agent is created. Nothing here runs an agent.
//!
//! - Agents stay on their owner's Home. A Runtime whose sign-in store is not
//!   its own data folder is a child of another Runtime and creates none.
//! - The Agent Host an agent is created for is installed from this Home's
//!   signed release, at the path that release records, and its manifest is
//!   signed by the one key that signed that release. An unsigned package is
//!   refused whatever `dev_mode` says, and so is one the release records but
//!   no key signed. Other configured publisher keys, and keys trusted only by
//!   this Home's own configuration, are not asked.
//!
//! This proves the package is the one the signed release installed at that
//! path. It does not hash the unpacked files.

use std::path::Path;

use elastos_common::CapsuleManifest;
use elastos_runtime::signature::{hash_content, SignatureVerifier};

use crate::agents::Refused;
use crate::auth::AgentHostPackage;

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
    pub(crate) fn unchecked_for_test(name: &str, registry_cid: &str) -> Self {
        Self(AgentHostPackage {
            name: name.to_string(),
            registry_cid: registry_cid.to_string(),
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

    let Ok(manifest) = std::fs::read(dir.join("capsule.json")) else {
        return Err(refuse("has no manifest"));
    };
    let Ok(manifest) = serde_json::from_slice::<CapsuleManifest>(&manifest) else {
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
    let Ok(content) = std::fs::read(dir.join(entrypoint)) else {
        return Err(refuse("has no entrypoint file"));
    };
    let key_signed = manifest.signature.is_some()
        && verifier
            .verify_capsule(&manifest, &hash_content(&content))
            .is_ok_and(|key| key.is_some());
    if !key_signed {
        return Err(refuse(
            "is not signed by the key that signed its installed release",
        ));
    }
    Ok(VerifiedAgentHost(AgentHostPackage {
        name: agent_host.to_string(),
        registry_cid: entry.cid.clone(),
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
}
