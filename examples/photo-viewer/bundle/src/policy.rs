//! The trust policy (review answer 6).
//!
//! The signed release source carries the table: publisher DID to the roles
//! (and optionally the names) it may ship, plus revoked DIDs and CIDs. It is
//! signed by the pinned release root DID. Local config may only add a dev
//! key, and only in dev mode; it cannot add roles to a release publisher,
//! lift a revocation, or add one.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::claim::canonical;
use crate::{sign, Refusal};

pub const POLICY_SCHEMA: &str = "elastos.release.trust-policy/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherEntry {
    pub did: String,
    pub roles: Vec<String>,
    /// When present, only these capsule names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    pub publishers: Vec<PublisherEntry>,
    pub revoked_dids: Vec<String>,
    pub revoked_cids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleasePolicy {
    pub schema: String,
    pub policy: ReleasePolicy,
    pub signer_did: String,
    pub signature: String,
}

/// The only thing a person's machine adds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub dev_mode: bool,
    #[serde(default)]
    pub dev_keys: Vec<PublisherEntry>,
}

/// What admission checks against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    pub publishers: Vec<PublisherEntry>,
    pub revoked_dids: Vec<String>,
    pub revoked_cids: Vec<String>,
}

impl ReleasePolicy {
    pub fn sign(self, root: &SigningKey) -> SignedReleasePolicy {
        let (signature, signer_did) = sign::sign(root, POLICY_SCHEMA, &canonical(&self));
        SignedReleasePolicy {
            schema: POLICY_SCHEMA.to_string(),
            policy: self,
            signer_did,
            signature,
        }
    }
}

impl SignedReleasePolicy {
    pub fn parse(bytes: &[u8]) -> Result<SignedReleasePolicy, Refusal> {
        let policy: SignedReleasePolicy = serde_json::from_slice(bytes)
            .map_err(|err| Refusal::PolicySignatureInvalid(format!("policy: {err}")))?;
        Ok(policy)
    }

    /// Verifies the policy against the pinned release root, not against the
    /// DID the document names for itself.
    pub fn verify(&self, release_root_did: &str) -> Result<&ReleasePolicy, Refusal> {
        if self.schema != POLICY_SCHEMA {
            return Err(Refusal::PolicySignatureInvalid(format!(
                "policy schema {:?}, expected {POLICY_SCHEMA}",
                self.schema
            )));
        }
        if self.signer_did != release_root_did {
            return Err(Refusal::PolicySignatureInvalid(format!(
                "policy signed by {}, expected the release root {release_root_did}",
                self.signer_did
            )));
        }
        sign::verify(
            release_root_did,
            POLICY_SCHEMA,
            &canonical(&self.policy),
            &self.signature,
        )
        .map_err(Refusal::PolicySignatureInvalid)?;
        Ok(&self.policy)
    }
}

pub fn effective_policy(
    release: &SignedReleasePolicy,
    release_root_did: &str,
    local: &LocalConfig,
) -> Result<TrustPolicy, Refusal> {
    let policy = release.verify(release_root_did)?;
    let mut publishers = policy.publishers.clone();
    if !local.dev_mode {
        if let Some(key) = local.dev_keys.first() {
            return Err(Refusal::DevKeyOutsideDevMode(key.did.clone()));
        }
    }
    for key in &local.dev_keys {
        let known =
            key.did == release_root_did || publishers.iter().any(|entry| entry.did == key.did);
        if known || policy.revoked_dids.contains(&key.did) {
            return Err(Refusal::DevKeyConflict(key.did.clone()));
        }
        publishers.push(key.clone());
    }
    Ok(TrustPolicy {
        publishers,
        revoked_dids: policy.revoked_dids.clone(),
        revoked_cids: policy.revoked_cids.clone(),
    })
}
