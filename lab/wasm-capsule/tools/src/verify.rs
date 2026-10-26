//! wc-004: the RUN side's one verify path, as library calls.
//!
//! [`verify_checked`] takes a [`CheckedBundle`] (the lab CID together with the
//! bytes cc-capsule-identity's one walk read), its in-memory name signature,
//! the accepted signer DIDs and the granted imports. Its checks, in order:
//!
//! 1. a bundle with no signature is refused as unsigned;
//! 2. cc-capsule-identity's `verify_checked_signature` checks the signature
//!    on the checked value: a canonical `did:key`, the accepted list, the
//!    signed name against the checked bytes, then Ed25519;
//! 3. the manifest's `entrypoint`, read from the checked `capsule.json` with
//!    the Runtime's `CapsuleManifest`, names the module among the checked
//!    entries;
//! 4. the cx-wasm-audit crate's `audit` reads that module's checked bytes,
//!    with the caller's granted imports passed to it unchanged.
//!
//! [`verify_bundle`] is `checked_bundle` and then [`verify_checked`], with no
//! check of its own, so the walk's refusals come first.
//!
//! The verifier holds no name, walk, hash, signature or import code: each
//! check is one call into the lane that owns it, and every refusal of theirs
//! passes through unchanged. It reads no file by a path: the checked value
//! already holds the bytes the name covers, so the module it audits is
//! exactly the module that was signed, even if the folder changes later.
//!
//! It answers only "do these bytes match this signed name, did an accepted key
//! sign it, and is every import granted". It never answers "may this run": it
//! makes no admission, launch or publisher-trust decision, and the granted
//! list is a lab stand-in, not admission.

use std::fmt;
use std::path::Path;

use capsule_identity::{
    checked_bundle, verify_checked_signature, BundleEntry, CheckedBundle, LabCid, NameSignature,
    Refusal as IdentityRefusal, MANIFEST_FILE,
};
use elastos_common::CapsuleManifest;
use wasm_capsule_audit::{audit, DeclaredImport, Refusal as AuditRefusal};

/// A bundle the verifier passed: the checked bundle and the import list the
/// audit returned for its entrypoint module (exactly the module's imports, in
/// order).
///
/// Its fields are private, it has no public constructor and no `&mut`
/// access, and it cannot be deserialized, so a value exists only as
/// [`verify_checked`] made it. It holds a name and bytes, never a decision:
/// it is no admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    checked: CheckedBundle,
    imports: Vec<DeclaredImport>,
}

impl VerifiedBundle {
    /// The lab CID the signature was checked against.
    pub fn cid(&self) -> LabCid {
        self.checked.cid()
    }

    /// The bytes that lab CID names, as the one walk read them.
    pub fn entries(&self) -> &[BundleEntry] {
        self.checked.entries()
    }

    /// The audit's own import list for the entrypoint module.
    pub fn imports(&self) -> &[DeclaredImport] {
        &self.imports
    }
}

/// Why the verifier refused a bundle. Each reason has its own variant and its
/// own text; the identity and audit refusals are carried unchanged and print
/// exactly as their own lanes print them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyRefusal {
    /// The bundle came with no signature.
    Unsigned,
    /// cc-capsule-identity refused: the walk, or the signature check.
    Identity(IdentityRefusal),
    /// The Runtime's `CapsuleManifest` could not read the checked
    /// `capsule.json`. The walk runs the same parse and refuses first, so a
    /// value from `checked_bundle` never meets this; it is kept so the
    /// verifier fails closed with a reason, never a panic.
    ManifestUnreadable { reason: String },
    /// No checked entry has the manifest's `entrypoint` path.
    EntrypointMissing { entrypoint: String },
    /// The cx-wasm-audit crate refused the entrypoint module.
    Audit(AuditRefusal),
}

impl fmt::Display for VerifyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyRefusal::Unsigned => {
                write!(
                    f,
                    "the bundle has no signature: an unsigned bundle is refused"
                )
            }
            VerifyRefusal::Identity(refusal) => write!(f, "{refusal}"),
            VerifyRefusal::ManifestUnreadable { reason } => write!(
                f,
                "the Runtime's CapsuleManifest could not read the checked {MANIFEST_FILE}: {reason}"
            ),
            VerifyRefusal::EntrypointMissing { entrypoint } => write!(
                f,
                "the manifest's entrypoint {entrypoint:?} is not a file in the bundle"
            ),
            VerifyRefusal::Audit(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for VerifyRefusal {}

/// Verify the checked bundle `checked` against `signature`, the `accepted`
/// signer DIDs and the `granted` imports. The checks and their order are in
/// the module docs; the first refusal is the answer.
pub fn verify_checked(
    checked: CheckedBundle,
    signature: Option<&NameSignature>,
    accepted: &[String],
    granted: &[DeclaredImport],
) -> Result<VerifiedBundle, VerifyRefusal> {
    let signature = signature.ok_or(VerifyRefusal::Unsigned)?;
    verify_checked_signature(&checked, signature, accepted).map_err(VerifyRefusal::Identity)?;
    let module = entrypoint_module(&checked)?;
    let imports = audit(module, granted).map_err(VerifyRefusal::Audit)?;
    Ok(VerifiedBundle { checked, imports })
}

/// Verify the bundle at `bundle`: cc-capsule-identity's `checked_bundle`, the
/// one walk, and then [`verify_checked`] on what it read. It holds no check of
/// its own, so a bundle the walk refuses is refused first, with the walk's
/// own reason.
pub fn verify_bundle(
    bundle: &Path,
    signature: Option<&NameSignature>,
    accepted: &[String],
    granted: &[DeclaredImport],
) -> Result<VerifiedBundle, VerifyRefusal> {
    let checked = checked_bundle(bundle).map_err(VerifyRefusal::Identity)?;
    verify_checked(checked, signature, accepted, granted)
}

/// The checked bytes of the module the manifest's `entrypoint` names. No
/// other entry stands in for it.
fn entrypoint_module(checked: &CheckedBundle) -> Result<&[u8], VerifyRefusal> {
    let entrypoint = manifest_entrypoint(checked)?;
    let module = checked
        .entries()
        .iter()
        .find(|entry| entry.path == entrypoint);
    match module {
        Some(entry) => Ok(&entry.content),
        None => Err(VerifyRefusal::EntrypointMissing { entrypoint }),
    }
}

/// The `entrypoint` of the checked `capsule.json`, read with the Runtime's
/// `CapsuleManifest`, the one reader of that file.
fn manifest_entrypoint(checked: &CheckedBundle) -> Result<String, VerifyRefusal> {
    let unreadable = |reason: String| VerifyRefusal::ManifestUnreadable { reason };
    let manifest = checked
        .entries()
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or_else(|| unreadable(format!("no {MANIFEST_FILE} entry")))?;
    let manifest: CapsuleManifest = serde_json::from_slice(&manifest.content)
        .map_err(|reason| unreadable(reason.to_string()))?;
    Ok(manifest.entrypoint)
}
