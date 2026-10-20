//! The trust policy (review answer 6, and the rollback and dev-key answers
//! of the P4b review).
//!
//! The signed release source carries the table: publisher DID to the roles
//! (and optionally the names) it may ship, plus revoked DIDs and CIDs. It is
//! signed by the pinned release root DID, carries a sequence number and an
//! expiry. A device keeps the highest sequence it has accepted and refuses a
//! lower one, so an old policy from before a revocation cannot be replayed;
//! the expiry stops a device being held on an old policy by never sending it
//! a new one.
//!
//! Local config may only add a dev key, only in dev mode. A dev key names
//! the capsules it may ship (never a whole role) and expires. Local config
//! cannot add roles to a release publisher, lift a revocation, or add one.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::claim::canonical;
use crate::{io, sign, Refusal};

pub const POLICY_SCHEMA: &str = "elastos.release.trust-policy/v1";

const DAY: u64 = 24 * 60 * 60;
/// A release policy may run at most this long past the time it is loaded.
pub const MAX_POLICY_LIFETIME_SECS: u64 = 90 * DAY;
/// A dev key may run at most this long past the time it is loaded.
pub const MAX_DEV_KEY_LIFETIME_SECS: u64 = 30 * DAY;

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
    /// Raised by every release of the policy; never reused.
    pub sequence: u64,
    /// Unix seconds. The policy is refused from this time on.
    pub expires_at: u64,
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

/// A development key: named capsules only, and an expiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevKey {
    pub did: String,
    pub roles: Vec<String>,
    pub names: Vec<String>,
    /// Unix seconds.
    pub expires_at: u64,
}

/// The only thing a person's machine adds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub dev_mode: bool,
    #[serde(default)]
    pub dev_keys: Vec<DevKey>,
}

/// One publisher admission may accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPublisher {
    pub did: String,
    pub roles: Vec<String>,
    pub names: Option<Vec<String>>,
    /// Set for dev keys.
    pub expires_at: Option<u64>,
}

/// What admission checks against. It keeps the floor it was accepted
/// against, and admission checks that floor again every time, so a policy
/// held since before a newer one was accepted is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustPolicy {
    pub sequence: u64,
    /// sha256 of the accepted release policy.
    pub sha256: String,
    pub floor: PolicyFloor,
    pub expires_at: u64,
    pub publishers: Vec<TrustedPublisher>,
    pub revoked_dids: Vec<String>,
    pub revoked_cids: Vec<String>,
}

/// The highest policy sequence this device has accepted, and the sha256 of
/// that policy, kept in one file. The Runtime would keep it in its own state.
///
/// Reading, checking and raising it happen under an exclusive lock on
/// `<path>.lock`, so two policies loaded at once cannot both read the old
/// floor and leave the lower one written. Each writer uses its own temporary
/// file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyFloor {
    path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorRecord {
    sequence: u64,
    sha256: String,
}

impl PolicyFloor {
    pub fn at(path: impl Into<PathBuf>) -> PolicyFloor {
        PolicyFloor { path: path.into() }
    }

    /// `None` before any policy was accepted. A record that does not parse
    /// is refused, not treated as none.
    pub fn seen(&self) -> Result<Option<(u64, String)>, Refusal> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(io(err, &self.path)),
        };
        let record: FloorRecord = serde_json::from_slice(&bytes)
            .map_err(|err| Refusal::Io(format!("{}: {err}", self.path.display())))?;
        Ok(Some((record.sequence, record.sha256)))
    }

    /// Held for the whole read, check and raise; released on drop.
    fn lock(&self) -> Result<std::fs::File, Refusal> {
        let path = sibling_path(&self.path, ".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|err| io(err, &path))?;
        file.lock().map_err(|err| io(err, &path))?;
        Ok(file)
    }

    fn raise(&self, sequence: u64, sha256: &str) -> Result<(), Refusal> {
        let record = FloorRecord {
            sequence,
            sha256: sha256.to_string(),
        };
        let temporary = sibling_path(
            &self.path,
            &format!(
                ".next-{}-{}",
                std::process::id(),
                hex::encode(rand::random::<[u8; 8]>())
            ),
        );
        std::fs::write(&temporary, serde_json::to_vec(&record).unwrap())
            .map_err(|err| io(err, &temporary))?;
        std::fs::rename(&temporary, &self.path).map_err(|err| io(err, &self.path))
    }
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    path.with_file_name(name)
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

/// Verifies the release policy, refuses an expired one or one older than the
/// floor, raises the floor, then adds the local dev keys. `now` is Unix
/// seconds.
pub fn effective_policy(
    release: &SignedReleasePolicy,
    release_root_did: &str,
    local: &LocalConfig,
    now: u64,
    floor: &PolicyFloor,
) -> Result<TrustPolicy, Refusal> {
    let policy = release.verify(release_root_did)?;
    if now >= policy.expires_at {
        return Err(Refusal::PolicyExpired {
            expires_at: policy.expires_at,
            now,
        });
    }
    if policy.expires_at > now.saturating_add(MAX_POLICY_LIFETIME_SECS) {
        return Err(Refusal::PolicyLifetimeTooLong {
            expires_at: policy.expires_at,
            latest: now.saturating_add(MAX_POLICY_LIFETIME_SECS),
        });
    }
    // Only a genuine, current, bounded policy moves the floor.
    let sha256 = hex::encode(Sha256::digest(canonical(policy)));
    let lock = floor.lock()?;
    match floor.seen()? {
        Some((seen, _)) if policy.sequence < seen => {
            return Err(Refusal::PolicyRollback {
                offered: policy.sequence,
                seen,
            });
        }
        Some((seen, seen_sha256)) if policy.sequence == seen && seen_sha256 != sha256 => {
            return Err(Refusal::PolicySequenceConflict(seen));
        }
        Some((seen, _)) if policy.sequence == seen => {}
        _ => floor.raise(policy.sequence, &sha256)?,
    }
    drop(lock);

    let mut publishers: Vec<TrustedPublisher> = policy
        .publishers
        .iter()
        .map(|entry| TrustedPublisher {
            did: entry.did.clone(),
            roles: entry.roles.clone(),
            names: entry.names.clone(),
            expires_at: None,
        })
        .collect();
    if !local.dev_mode {
        if let Some(key) = local.dev_keys.first() {
            return Err(Refusal::DevKeyOutsideDevMode(key.did.clone()));
        }
    }
    for key in &local.dev_keys {
        if key.names.is_empty() {
            return Err(Refusal::DevKeyUnscoped(key.did.clone()));
        }
        if now >= key.expires_at {
            return Err(Refusal::DevKeyExpired {
                did: key.did.clone(),
                expires_at: key.expires_at,
            });
        }
        if key.expires_at > now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS) {
            return Err(Refusal::DevKeyLifetimeTooLong {
                did: key.did.clone(),
                expires_at: key.expires_at,
                latest: now.saturating_add(MAX_DEV_KEY_LIFETIME_SECS),
            });
        }
        let known =
            key.did == release_root_did || publishers.iter().any(|entry| entry.did == key.did);
        if known || policy.revoked_dids.contains(&key.did) {
            return Err(Refusal::DevKeyConflict(key.did.clone()));
        }
        publishers.push(TrustedPublisher {
            did: key.did.clone(),
            roles: key.roles.clone(),
            names: Some(key.names.clone()),
            expires_at: Some(key.expires_at),
        });
    }
    Ok(TrustPolicy {
        sequence: policy.sequence,
        sha256,
        floor: floor.clone(),
        expires_at: policy.expires_at,
        publishers,
        revoked_dids: policy.revoked_dids.clone(),
        revoked_cids: policy.revoked_cids.clone(),
    })
}
