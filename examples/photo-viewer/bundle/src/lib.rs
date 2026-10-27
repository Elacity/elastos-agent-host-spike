//! Spike-only capsule bundle tool (P4b).
//!
//! A capsule is named by the CID of its closure listing: every file it ships,
//! with its path, size and sha256, as canonical JSON. A publisher DID signs a
//! detached, minimal claim for that CID. Rebuilders may add separate signed
//! provenance records that name the CID. Admission verifies the closure and
//! the claim, applies the trust policy (a signed release table of publisher
//! DID to roles with revocations, a sequence floor against rollback and an
//! expiry; dev keys only in dev mode, named capsules only, expiring), refuses a lower
//! version of an installed name, then stages a read-only copy under its CID,
//! verifies that copy, and loads only from it.
//!
//! [`pack`] makes the closure out of a capsule's source folder: only what the
//! capsule runs from, so its CID does not change with its tests or source.
//!
//! Every refusal has a code ([`Refusal::code`]) and names what was expected.

pub mod admit;
pub mod cid;
pub mod claim;
pub mod listing;
pub mod pack;
pub mod policy;
pub mod provenance;
pub mod sign;
pub mod testing;

pub use admit::{admit, load, resolve_requires, Admitted, Installed, Loaded};
// This test code stands in for the Runtime's launch by CID, which does not exist yet.
pub use admit::{
    admit_staged_for_stand_in, bind_content_stand_in, select_stand_in_dependencies,
    validate_content_stand_in, StandInDependencies, StandInResolveManifest,
};
pub use cid::cid_v1_raw_sha256;
pub use claim::{Claim, SignedClaim, CLAIM_SCHEMA};
pub use listing::{
    check_unique_under_case_folding, closure_cid, list_closure, listing_bytes, Entry,
    LISTING_SCHEMA,
};
pub use pack::pack;
pub use policy::{
    effective_policy, DevKey, LocalConfig, PolicyFloor, PublisherEntry, ReleasePolicy,
    SignedReleasePolicy, TrustPolicy, TrustedPublisher, MAX_DEV_KEY_LIFETIME_SECS,
    MAX_POLICY_LIFETIME_SECS, POLICY_SCHEMA,
};
pub use provenance::{Provenance, SignedProvenance, PROVENANCE_SCHEMA};

/// Why a capsule, claim, policy or staged copy is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// A path segment is empty, `.` or `..`, not UTF-8, or has `/`, `\` or a
    /// control character.
    PathInvalid(String),
    /// A non-ASCII path is not in Unicode NFC.
    PathNotNfc(String),
    /// Two paths are equal under Unicode case folding.
    PathCaseCollision(String, String),
    /// A symlink, FIFO, socket or device file.
    SpecialFile(String),
    /// A folder on the way to what is read or written is a symlink: the root
    /// itself, or any folder between the root and a file. Nothing is read or
    /// written through a link, because every check after it would describe
    /// another place.
    SymlinkInPath(String),
    /// The closure has no `capsule.json` at its root.
    ManifestMissing,
    /// The claim, the manifest or a version does not parse as required.
    ClaimMalformed(String),
    /// The recomputed closure CID is not the one claimed.
    CidMismatch { claimed: String, computed: String },
    /// The signature does not verify for the named DID.
    SignatureInvalid(String),
    /// The claim's name, version or role differ from the closure's manifest.
    ClaimManifestMismatch(String),
    /// The release policy is not signed by the pinned release root.
    PolicySignatureInvalid(String),
    /// The release policy's expiry has passed.
    PolicyExpired { expires_at: u64, now: u64 },
    /// The release policy runs more than 90 days past now.
    PolicyLifetimeTooLong { expires_at: u64, latest: u64 },
    /// The release policy's sequence is below the highest this device accepted.
    PolicyRollback { offered: u64, seen: u64 },
    /// Admission with a policy older than the floor (or with no floor): a
    /// newer policy was accepted since, or the floor is gone.
    PolicyStale { sequence: u64, seen: Option<u64> },
    /// Another policy with the same sequence was already accepted.
    PolicySequenceConflict(u64),
    /// A local dev key outside dev mode.
    DevKeyOutsideDevMode(String),
    /// A dev key that names no capsule (it would ship a whole role).
    DevKeyUnscoped(String),
    /// A dev key that runs more than 30 days past now.
    DevKeyLifetimeTooLong {
        did: String,
        expires_at: u64,
        latest: u64,
    },
    /// A dev key past its expiry.
    DevKeyExpired { did: String, expires_at: u64 },
    /// A local dev key that is already a release publisher.
    DevKeyConflict(String),
    /// No trust policy entry for the publisher DID.
    PublisherUntrusted(String),
    /// The policy does not let this publisher ship this role or name.
    PublisherRoleRefused {
        publisher: String,
        role: String,
        name: String,
    },
    /// The publisher DID is revoked.
    PublisherRevoked(String),
    /// The release policy lists this publisher DID in more than one entry.
    /// One entry may list several roles and names.
    PublisherListedTwice(String),
    /// The CID is revoked.
    CidRevoked(String),
    /// An installed capsule of the same name has a higher version.
    VersionDowngrade {
        name: String,
        installed: String,
        offered: String,
    },
    /// An installed capsule of the same name and version has another CID.
    VersionConflict {
        name: String,
        version: String,
        installed: String,
        offered: String,
    },
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// The content CID is absent from the staged store.
    StagedMissing { cid: String },
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// The staged content has no detached admission claim.
    ClaimMissing { cid: String },
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// The content pins a different viewer from the launch selection.
    ViewerMismatch {
        cid: String,
        actual: String,
        expected: String,
    },
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// A resolved dependency differs from the selected CID, role or execution.
    LaunchBindingInvalid { cid: String, role: String },
    /// The staged copy does not hash to its CID.
    StagedMismatch { cid: String, computed: String },
    /// The staged copy has a writable file or directory.
    StagedNotReadOnly(String),
    /// A capsule requirement with no `cid`.
    CoreUnpinned(String),
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// A passive content viewer needs its own CID pin.
    ContentCoreUnpinned(String),
    /// The content profile or its viewer binding is malformed.
    ContentBindingInvalid { cid: String, detail: String },
    /// No installed capsule has the required name and CID.
    CoreMissing { name: String, cid: String },
    /// The installed capsule of that name, or with that CID, is another one.
    CoreMismatch {
        name: String,
        required: String,
        installed: String,
    },
    /// A provenance record names another CID.
    ProvenanceCidMismatch { expected: String, named: String },
    /// Pack: the manifest names no entrypoint, the entrypoint is not in the
    /// source, or a page's entrypoint is not in a folder of its own.
    PackEntrypointMissing(String),
    /// Pack: the folder to pack into already exists.
    PackDestinationExists(String),
    /// A filesystem error.
    Io(String),
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::PathInvalid(_) => "path_invalid",
            Refusal::PathNotNfc(_) => "path_not_nfc",
            Refusal::PathCaseCollision(..) => "path_case_collision",
            Refusal::SpecialFile(_) => "special_file",
            Refusal::SymlinkInPath(_) => "symlink_in_path",
            Refusal::ManifestMissing => "manifest_missing",
            Refusal::ClaimMalformed(_) => "claim_malformed",
            Refusal::CidMismatch { .. } => "cid_mismatch",
            Refusal::SignatureInvalid(_) => "signature_invalid",
            Refusal::ClaimManifestMismatch(_) => "claim_manifest_mismatch",
            Refusal::PolicySignatureInvalid(_) => "policy_signature_invalid",
            Refusal::PolicyExpired { .. } => "policy_expired",
            Refusal::PolicyLifetimeTooLong { .. } => "policy_lifetime_too_long",
            Refusal::PolicyRollback { .. } => "policy_rollback",
            Refusal::PolicyStale { .. } => "policy_stale",
            Refusal::PolicySequenceConflict(_) => "policy_sequence_conflict",
            Refusal::DevKeyOutsideDevMode(_) => "dev_key_outside_dev_mode",
            Refusal::DevKeyUnscoped(_) => "dev_key_unscoped",
            Refusal::DevKeyLifetimeTooLong { .. } => "dev_key_lifetime_too_long",
            Refusal::DevKeyExpired { .. } => "dev_key_expired",
            Refusal::DevKeyConflict(_) => "dev_key_conflict",
            Refusal::PublisherUntrusted(_) => "publisher_untrusted",
            Refusal::PublisherRoleRefused { .. } => "publisher_role_refused",
            Refusal::PublisherRevoked(_) => "publisher_revoked",
            Refusal::PublisherListedTwice(_) => "publisher_listed_twice",
            Refusal::CidRevoked(_) => "cid_revoked",
            Refusal::VersionDowngrade { .. } => "version_downgrade",
            Refusal::VersionConflict { .. } => "version_conflict",
            Refusal::StagedMissing { .. } => "staged_missing",
            Refusal::ClaimMissing { .. } => "claim_missing",
            Refusal::ViewerMismatch { .. } => "viewer_mismatch",
            Refusal::LaunchBindingInvalid { .. } => "launch_binding_invalid",
            Refusal::StagedMismatch { .. } => "staged_mismatch",
            Refusal::StagedNotReadOnly(_) => "staged_not_read_only",
            Refusal::CoreUnpinned(_) => "core_unpinned",
            // This test code stands in for the Runtime's launch by CID, which does not exist yet.
            Refusal::ContentCoreUnpinned(_) => "core_unpinned",
            Refusal::ContentBindingInvalid { .. } => "content_binding_invalid",
            Refusal::CoreMissing { .. } => "core_missing",
            Refusal::CoreMismatch { .. } => "core_mismatch",
            Refusal::ProvenanceCidMismatch { .. } => "provenance_cid_mismatch",
            Refusal::PackEntrypointMissing(_) => "pack_entrypoint_missing",
            Refusal::PackDestinationExists(_) => "pack_destination_exists",
            Refusal::Io(_) => "io",
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // This test code stands in for the Runtime's launch by CID, which does not exist yet.
            Refusal::StagedMissing { cid } => write!(f,
                "staged_missing: Content CID {cid} is absent from the staged store; admit that exact capsule first."),
            Refusal::ClaimMissing { cid } => write!(f,
                "claim_missing: Content {cid} has no admission claim; admit the signed capsule first."),
            Refusal::ViewerMismatch { cid, actual, expected } => write!(f,
                "viewer_mismatch: Content {cid} requires viewer {actual}; this launch selected {expected}."),
            Refusal::LaunchBindingInvalid { cid, role } => write!(f,
                "launch_binding_invalid: Resolved {cid} does not match the selected {role} for this stand-in launch."),
            Refusal::ContentCoreUnpinned(cid) => write!(f,
                "core_unpinned: Content {cid} must pin its viewer with viewer.cid; a name alone cannot select it."),
            Refusal::ContentBindingInvalid { cid, detail } => write!(f,
                "content_binding_invalid: Content {cid} needs the passive photo profile and one viewer CID: {detail}."),
            Refusal::CoreMissing { name, cid } => write!(f,
                "core_missing: Required {name} at {cid} is absent; admit that exact dependency."),
            Refusal::CoreMismatch { name, required, installed } => write!(f,
                "core_mismatch: Required {name} at {required} differs from installed {installed}."),
            // The path named is the link; the caller needs the path it stands
            // for, which the same check accepts.
            Refusal::SymlinkInPath(_) => write!(
                f,
                "{}: {self:?}; pass the physical path instead, for example /private/tmp for /tmp",
                self.code()
            ),
            _ => write!(f, "{}: {self:?}", self.code()),
        }
    }
}

impl std::error::Error for Refusal {}

pub(crate) fn io(err: std::io::Error, what: &std::path::Path) -> Refusal {
    Refusal::Io(format!("{}: {err}", what.display()))
}
