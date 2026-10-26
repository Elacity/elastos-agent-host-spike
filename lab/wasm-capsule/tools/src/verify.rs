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
//! The value keeps which checked entry step 3 found, and
//! [`VerifiedBundle::entrypoint`] returns it, so a caller such as the runner
//! never reads the manifest again: the verifier holds the one manifest read.
//!
//! [`verify_bundle`] is `checked_bundle` and then [`verify_checked`], with no
//! check of its own, so the walk's refusals come first.
//!
//! The verifier holds no name, walk, hash, signature or import code: each
//! check is one call into the lane that owns it, and every refusal of theirs
//! passes through unchanged. It reads no bundle file by path: the checked
//! value already holds the bytes the name covers, so the module it audits is
//! exactly the module that was signed, even if the folder changes later. The
//! one file it reads by a path is the lab grants file (see wc-009a below).
//!
//! It answers only "do these bytes match this signed name, did an accepted key
//! sign it, and is every import granted". It never answers "may this run": it
//! makes no admission, launch or publisher-trust decision, and the granted
//! list is a lab stand-in, not admission.
//!
//! wc-009a: the module's own import section in the signed `capsule.wasm` is the
//! declaration (Rong's ruling (c)); the audit is its one reader. The granted
//! list comes from the lab grants file, read by [`read_grants`], the one grants
//! reader. It is the one place in this module that reads a file by a path: the
//! grants file is the caller's input, outside the bundle, never part of the
//! lab CID, and labelled "lab stand-in, not admission". An import is linked
//! only if it is in the signed module and granted: [`VerifiedBundle::imports`]
//! is the audit's own list, and [`VerifiedBundle::unused_grants`] the grants
//! the module does not import, in file order, computed once from that list.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use capsule_identity::{
    checked_bundle, verify_checked_signature, BundleEntry, CheckedBundle, LabCid, NameSignature,
    Refusal as IdentityRefusal, MANIFEST_FILE,
};
use elastos_common::CapsuleManifest;
use serde_json::{Map, Value};
use wasm_capsule_audit::{audit, Refusal as AuditRefusal};

/// One import, `module` and `name`: the audit's own type, which the grants
/// reader returns and the verifier takes.
pub use wasm_capsule_audit::DeclaredImport;

/// The lab grants file's `schema`, exactly.
pub const GRANTS_SCHEMA: &str = "wc-009.lab-grants/v1";

/// The lab grants file's `label`, exactly: the file is a lab stand-in for the
/// Runtime's grant decision, never admission.
pub const GRANTS_LABEL: &str = "lab stand-in, not admission";

/// The grants file's top-level keys; no other key is allowed.
const GRANTS_KEYS: [&str; 3] = ["schema", "label", "imports"];

/// The keys of one grant; an entry has exactly these two.
const GRANT_KEYS: [&str; 2] = ["module", "name"];

/// A bundle the verifier passed: the checked bundle, which of its entries is
/// the entrypoint module the audit read, the import list the audit returned
/// for that module (exactly the module's imports, in order, each granted), and
/// the grants the module does not import, in the caller's order.
///
/// Its fields are private, it has no public constructor and no `&mut`
/// access, and it cannot be deserialized, so a value exists only as
/// [`verify_checked`] made it. It holds a name and bytes, never a decision:
/// it is no admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    checked: CheckedBundle,
    entrypoint: usize,
    imports: Vec<DeclaredImport>,
    unused: Vec<DeclaredImport>,
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

    /// The checked entry the manifest's `entrypoint` names: the module the
    /// audit read. The verifier found it with its one manifest read, so no
    /// caller reads the manifest again.
    pub fn entrypoint(&self) -> &BundleEntry {
        &self.checked.entries()[self.entrypoint]
    }

    /// The audit's own import list for the entrypoint module: each import is
    /// in the signed module and granted, so this is what is linked.
    pub fn imports(&self) -> &[DeclaredImport] {
        &self.imports
    }

    /// The grants the entrypoint module does not import, in the order the
    /// caller gave them. They link nothing; they are reported.
    pub fn unused_grants(&self) -> &[DeclaredImport] {
        &self.unused
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
    let entrypoint = entrypoint_index(&checked)?;
    let module = &checked.entries()[entrypoint].content;
    let imports = audit(module, granted).map_err(VerifyRefusal::Audit)?;
    let unused = grants_not_imported(granted, &imports);
    Ok(VerifiedBundle {
        checked,
        entrypoint,
        imports,
        unused,
    })
}

/// The grants in `granted` that are not in the audit's list `imports`, in
/// `granted`'s order. No import is read again: `imports` is the audit's own.
fn grants_not_imported(
    granted: &[DeclaredImport],
    imports: &[DeclaredImport],
) -> Vec<DeclaredImport> {
    granted
        .iter()
        .filter(|grant| !imports.contains(grant))
        .cloned()
        .collect()
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

/// Where, among the checked entries, the module the manifest's `entrypoint`
/// names is. No other entry stands in for it.
fn entrypoint_index(checked: &CheckedBundle) -> Result<usize, VerifyRefusal> {
    let entrypoint = manifest_entrypoint(checked)?;
    let module = checked
        .entries()
        .iter()
        .position(|entry| entry.path == entrypoint);
    match module {
        Some(index) => Ok(index),
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

/// A grants file the reader refused: the path it was given, and why.
#[derive(Debug)]
pub struct GrantsRefusal {
    pub path: PathBuf,
    pub reason: GrantsReason,
}

/// Why the grants reader refused a file. Each reason has its own variant and
/// its own text.
#[derive(Debug)]
pub enum GrantsReason {
    /// The file could not be read; the OS cause is kept.
    Unreadable(io::Error),
    /// The bytes are not JSON.
    NotJson { reason: String },
    /// The JSON document is not an object.
    NotAnObject,
    /// The document has a key other than `schema`, `label` and `imports`.
    UnknownKey { key: String },
    /// The document lacks one of `schema`, `label` and `imports`.
    MissingKey { key: &'static str },
    /// `schema` is not [`GRANTS_SCHEMA`]; the value found, as JSON.
    WrongSchema { schema: Value },
    /// `label` is not [`GRANTS_LABEL`]; the value found, as JSON.
    WrongLabel { label: Value },
    /// `imports` is not a list.
    ImportsNotAList,
    /// The entry at `index` of `imports` is not an object of exactly two
    /// strings, `module` and `name`.
    EntryNotAPair { index: usize },
    /// The same `module` and `name` are granted twice.
    DuplicateGrant { module: String, name: String },
}

impl fmt::Display for GrantsReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantsReason::Unreadable(error) => {
                write!(f, "the grants file cannot be read: {error}")
            }
            GrantsReason::NotJson { reason } => {
                write!(f, "the grants file is not JSON: {reason}")
            }
            GrantsReason::NotAnObject => write!(f, "the grants file is not a JSON object"),
            GrantsReason::UnknownKey { key } => {
                write!(f, "the grants file has an unknown key {key:?}")
            }
            GrantsReason::MissingKey { key } => {
                write!(f, "the grants file has no {key:?} key")
            }
            GrantsReason::WrongSchema { schema } => write!(
                f,
                "the grants file's schema is {schema}, not {GRANTS_SCHEMA:?}"
            ),
            GrantsReason::WrongLabel { label } => write!(
                f,
                "the grants file's label is {label}, not {GRANTS_LABEL:?}"
            ),
            GrantsReason::ImportsNotAList => {
                write!(f, "the grants file's imports is not a list")
            }
            GrantsReason::EntryNotAPair { index } => write!(
                f,
                "grant {index} is not an object of exactly two strings, module and name"
            ),
            GrantsReason::DuplicateGrant { module, name } => {
                write!(f, "the grant {module}.{name} is listed twice")
            }
        }
    }
}

impl fmt::Display for GrantsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

impl std::error::Error for GrantsRefusal {}

/// Read the lab grants file at `path`: one read, then a parse from memory.
/// The file is exactly `{"schema": "wc-009.lab-grants/v1", "label": "lab
/// stand-in, not admission", "imports": [{"module": "...", "name": "..."}]}`;
/// an empty `imports` list is valid. The grants come back in file order. The
/// first refusal is the answer, with the path and its own reason.
pub fn read_grants(path: &Path) -> Result<Vec<DeclaredImport>, GrantsRefusal> {
    let refusal = |reason| GrantsRefusal {
        path: path.to_path_buf(),
        reason,
    };
    let bytes = fs::read(path).map_err(|error| refusal(GrantsReason::Unreadable(error)))?;
    parse_grants(&bytes).map_err(refusal)
}

/// The grants in `bytes`, checked by hand against the one file form: the
/// document, its keys, the schema, the label, then each entry in order.
fn parse_grants(bytes: &[u8]) -> Result<Vec<DeclaredImport>, GrantsReason> {
    let document: Value = serde_json::from_slice(bytes).map_err(|error| GrantsReason::NotJson {
        reason: error.to_string(),
    })?;
    let document = document.as_object().ok_or(GrantsReason::NotAnObject)?;
    if let Some(key) = document
        .keys()
        .find(|key| !GRANTS_KEYS.contains(&key.as_str()))
    {
        return Err(GrantsReason::UnknownKey { key: key.clone() });
    }
    let schema = grants_key(document, "schema")?;
    let label = grants_key(document, "label")?;
    let imports = grants_key(document, "imports")?;
    if schema.as_str() != Some(GRANTS_SCHEMA) {
        return Err(GrantsReason::WrongSchema {
            schema: schema.clone(),
        });
    }
    if label.as_str() != Some(GRANTS_LABEL) {
        return Err(GrantsReason::WrongLabel {
            label: label.clone(),
        });
    }
    let entries = imports.as_array().ok_or(GrantsReason::ImportsNotAList)?;
    let mut granted: Vec<DeclaredImport> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let grant = grant_entry(entry).ok_or(GrantsReason::EntryNotAPair { index })?;
        if granted.contains(&grant) {
            return Err(GrantsReason::DuplicateGrant {
                module: grant.module,
                name: grant.name,
            });
        }
        granted.push(grant);
    }
    Ok(granted)
}

/// The value of the required top-level `key`.
fn grants_key<'a>(
    document: &'a Map<String, Value>,
    key: &'static str,
) -> Result<&'a Value, GrantsReason> {
    document.get(key).ok_or(GrantsReason::MissingKey { key })
}

/// One grant: an object of exactly the two keys `module` and `name`, each a
/// string. Anything else is no grant.
fn grant_entry(entry: &Value) -> Option<DeclaredImport> {
    let entry = entry.as_object()?;
    if entry.len() != GRANT_KEYS.len() {
        return None;
    }
    Some(DeclaredImport {
        module: entry.get(GRANT_KEYS[0])?.as_str()?.to_owned(),
        name: entry.get(GRANT_KEYS[1])?.as_str()?.to_owned(),
    })
}
