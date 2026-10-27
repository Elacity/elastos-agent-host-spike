//! wc-004: the RUN side's one verify path, as library calls.
//!
//! [`verify_checked`] takes a [`CheckedBundle`] (the lab CID together with the
//! bytes cc-capsule-identity's one walk read), its in-memory name signature,
//! and the accepted signer DIDs. Its checks, in order:
//!
//! 1. a bundle with no signature is refused as unsigned;
//! 2. cc-capsule-identity's `verify_checked_signature` checks the signature
//!    on the checked value: a canonical `did:key`, the accepted list, the
//!    signed name against the checked bytes, then Ed25519;
//! 3. the manifest's `entrypoint`, read from the checked `capsule.json` with
//!    the Runtime's `CapsuleManifest`, names the module among the checked
//!    entries;
//! 4. the cx-wasm-audit crate's `audit` reads that module's checked bytes,
//!    with an empty declared list (task 065): the module may import nothing,
//!    and its first import is refused by its own name.
//!
//! The value keeps which checked entry step 3 found, and
//! [`VerifiedBundle::entrypoint`] returns it, so a caller such as the runner
//! never reads the manifest again: the verifier holds the one manifest read.
//! wc-010b: that same read also keeps the manifest's `resources.memory_mb`
//! (the Runtime's field, default 64 when the key is absent), and
//! [`VerifiedBundle::memory_mb`] returns it as read; the runner turns it into
//! an engine's memory cap. It is a resource budget, never an admission
//! decision.
//!
//! [`verify_bundle`] is `checked_bundle` and then [`verify_checked`], with no
//! check of its own, so the walk's refusals come first.
//!
//! The verifier holds no name, walk, hash, signature or import code: each
//! check is one call into the lane that owns it, and every refusal of theirs
//! passes through unchanged. It reads no bundle file by path: the checked
//! value already holds the bytes the name covers, so the module it audits is
//! exactly the module that was signed, even if the folder changes later. The
//! one file it reads by a path is the lab grants file (see task 065 below).
//!
//! It answers only "do these bytes match this signed name, did an accepted key
//! sign it, and does its module import nothing". It never answers "may this
//! run": it makes no admission, launch or publisher-trust decision.
//!
//! The module's own import section in the signed `capsule.wasm` is the
//! declaration (Rong's ruling (c)); the audit is its one reader. Task 065
//! (Rong's WC-1 and WC-2): the Runtime refuses every core-module import, so
//! the lab grants none. The audit gets an empty list, and a module with any
//! core import is refused with the audit's own `undeclared import
//! <module>.<name>`, before any engine starts.
//!
//! Task 064 (wc-009b, first half): the Bus path, the only import path.
//! The contract already exists: world `product-capsule-v1` of package
//! `elastos:bus@1.0.0` (`elastos/wit/elastos-bus-v1.wit`). [`BUS_V1_INTERFACES`]
//! holds its five import names, equal to the Runtime's `ALLOWED_BUS_IMPORTS`,
//! and [`bus_imports`] passes a component to cx-wasm-audit's `audit_component`
//! with that list, with no check of its own. No Bus host exists in the lab, and
//! no engine links or runs a component. A lab stand-in, not admission.
//!
//! Task 065: a lab grant names a `resource` and its `actions`, exactly as the
//! WIT `capability-request` does (`elastos/wit/elastos-bus-v1.wit`), in the lab
//! grants file `wc-009.lab-grants/v3`. [`read_grants`] is its one reader and the
//! one place in this module that reads a file by a path: the file is the
//! caller's input, outside the bundle, never part of the lab CID, and labelled
//! "lab stand-in, not admission". Nothing in the runner reads it: the lab has
//! no Bus host, mints no grant and checks none at run time.

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
use wasm_capsule_audit::{audit, audit_component, Refusal as AuditRefusal};

/// The Bus v1 interfaces a capsule may import, in the Runtime's order: the
/// imports of world `product-capsule-v1` in `elastos/wit/elastos-bus-v1.wit`
/// plus their shared `types`, exactly the Runtime's `ALLOWED_BUS_IMPORTS` in
/// `elastos/crates/elastos-server/src/component.rs` (a test holds the two
/// equal). `lifecycle` is the world's export, so it is not here. A lab
/// stand-in, not admission.
pub const BUS_V1_INTERFACES: [&str; 5] = [
    "elastos:bus/types@1.0.0",
    "elastos:bus/runtime@1.0.0",
    "elastos:bus/identity@1.0.0",
    "elastos:bus/capabilities@1.0.0",
    "elastos:bus/providers@1.0.0",
];

/// The Bus interfaces the lab would link for `component`: cx-wasm-audit's
/// `audit_component` with [`BUS_V1_INTERFACES`], and nothing else. Its list is
/// the component's own import names in section order; its refusal (an import
/// outside Bus v1, or bytes that are not a component, a core module too) is
/// returned as [`VerifyRefusal::Audit`], unchanged. No Bus host exists in the
/// lab, so nothing is linked. A lab stand-in, not admission.
pub fn bus_imports(component: &[u8]) -> Result<Vec<String>, VerifyRefusal> {
    audit_component(component, &BUS_V1_INTERFACES).map_err(VerifyRefusal::Audit)
}

/// The lab grants file's `schema`, exactly.
pub const GRANTS_SCHEMA: &str = "wc-009.lab-grants/v3";

/// The lab grants file's `label`, exactly: the file is a lab stand-in for the
/// Runtime's grant decision, never admission.
pub const GRANTS_LABEL: &str = "lab stand-in, not admission";

/// The grants file's top-level keys; no other key is allowed.
const GRANTS_KEYS: [&str; 3] = ["schema", "label", "grants"];

/// The keys of one grant, as the WIT `capability-request` names them; an entry
/// has exactly these two.
const GRANT_KEYS: [&str; 2] = ["resource", "actions"];

/// The keys of a v2 grant (task 031), retired by task 065: an entry holding
/// one is refused by that key.
const RETIRED_GRANT_KEYS: [&str; 3] = ["module", "name", "right"];

/// One lab grant: a `resource` and its `actions`, as the WIT
/// `capability-request` names them (`resource-uri` and `action` are strings).
/// The lab mints and checks no grant: a lab stand-in, not admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabGrant {
    pub resource: String,
    pub actions: Vec<String>,
}

/// A bundle the verifier passed: the checked bundle, which of its entries is
/// the entrypoint module the audit read (it imports nothing), and the
/// manifest's declared `resources.memory_mb`.
///
/// Its fields are private, it has no public constructor and no `&mut`
/// access, and it cannot be deserialized, so a value exists only as
/// [`verify_checked`] made it. It holds a name and bytes, never a decision:
/// it is no admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedBundle {
    checked: CheckedBundle,
    entrypoint: usize,
    memory_mb: u32,
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

    /// The manifest's declared `resources.memory_mb`, as the verifier's one
    /// manifest read found it: the Runtime's default, 64, when the manifest
    /// has no `resources` key.
    pub fn memory_mb(&self) -> u32 {
        self.memory_mb
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
    /// The cx-wasm-audit crate refused the entrypoint module, or (from
    /// [`bus_imports`]) a component.
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

/// Verify the checked bundle `checked` against `signature` and the `accepted`
/// signer DIDs. The checks and their order are in the module docs; the first
/// refusal is the answer. Task 065: no core-module import is granted, so the
/// one `audit` call gets an empty list.
pub fn verify_checked(
    checked: CheckedBundle,
    signature: Option<&NameSignature>,
    accepted: &[String],
) -> Result<VerifiedBundle, VerifyRefusal> {
    let signature = signature.ok_or(VerifyRefusal::Unsigned)?;
    verify_checked_signature(&checked, signature, accepted).map_err(VerifyRefusal::Identity)?;
    let (entrypoint, memory_mb) = entrypoint_index(&checked)?;
    let module = &checked.entries()[entrypoint].content;
    audit(module, &[]).map_err(VerifyRefusal::Audit)?;
    Ok(VerifiedBundle {
        checked,
        entrypoint,
        memory_mb,
    })
}

/// Verify the bundle at `bundle`: cc-capsule-identity's `checked_bundle`, the
/// one walk, and then [`verify_checked`] on what it read. It holds no check of
/// its own, so a bundle the walk refuses is refused first, with the walk's
/// own reason.
pub fn verify_bundle(
    bundle: &Path,
    signature: Option<&NameSignature>,
    accepted: &[String],
) -> Result<VerifiedBundle, VerifyRefusal> {
    let checked = checked_bundle(bundle).map_err(VerifyRefusal::Identity)?;
    verify_checked(checked, signature, accepted)
}

/// Where, among the checked entries, the module the manifest's `entrypoint`
/// names is, and the manifest's declared `resources.memory_mb`, both from the
/// one manifest read. No other entry stands in for the module.
fn entrypoint_index(checked: &CheckedBundle) -> Result<(usize, u32), VerifyRefusal> {
    let (entrypoint, memory_mb) = manifest_entrypoint(checked)?;
    let module = checked
        .entries()
        .iter()
        .position(|entry| entry.path == entrypoint);
    match module {
        Some(index) => Ok((index, memory_mb)),
        None => Err(VerifyRefusal::EntrypointMissing { entrypoint }),
    }
}

/// The `entrypoint` and the `resources.memory_mb` of the checked
/// `capsule.json`, read with the Runtime's `CapsuleManifest`, the one reader
/// of that file, in one parse.
fn manifest_entrypoint(checked: &CheckedBundle) -> Result<(String, u32), VerifyRefusal> {
    let unreadable = |reason: String| VerifyRefusal::ManifestUnreadable { reason };
    let manifest = checked
        .entries()
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or_else(|| unreadable(format!("no {MANIFEST_FILE} entry")))?;
    let manifest: CapsuleManifest = serde_json::from_slice(&manifest.content)
        .map_err(|reason| unreadable(reason.to_string()))?;
    Ok((manifest.entrypoint, manifest.resources.memory_mb))
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
    /// The document has a key other than `schema`, `label` and `grants`.
    UnknownKey { key: String },
    /// The document lacks one of `schema`, `label` and `grants`.
    MissingKey { key: &'static str },
    /// `schema` is not [`GRANTS_SCHEMA`]; the value found, as JSON.
    WrongSchema { schema: Value },
    /// `label` is not [`GRANTS_LABEL`]; the value found, as JSON.
    WrongLabel { label: Value },
    /// `grants` is not a list.
    GrantsNotAList,
    /// The entry at `index` of `grants` holds `key`, a key of the retired v2
    /// grant (`module`, `name` or `right`).
    RetiredKey { index: usize, key: &'static str },
    /// The entry at `index` of `grants` is not an object of exactly
    /// `resource`, a string, and `actions`, a list of strings.
    EntryNotAGrant { index: usize },
    /// The entry at `index` of `grants` names an empty resource.
    EmptyResource { index: usize },
    /// The grant of `resource` names no action.
    EmptyActions { resource: String },
    /// The grant of `resource` names an empty action.
    EmptyAction { resource: String },
    /// The grant of `resource` names `action` twice.
    RepeatedAction { resource: String, action: String },
    /// The same `resource` is granted twice.
    DuplicateResource { resource: String },
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
            GrantsReason::GrantsNotAList => {
                write!(f, "the grants file's grants is not a list")
            }
            GrantsReason::RetiredKey { index, key } => write!(
                f,
                "grant {index} has the retired key {key:?}: a lab grant names resource and actions, as capability-request"
            ),
            GrantsReason::EntryNotAGrant { index } => write!(
                f,
                "grant {index} is not an object of exactly resource, a string, and actions, a list of strings"
            ),
            GrantsReason::EmptyResource { index } => {
                write!(f, "grant {index} names an empty resource")
            }
            GrantsReason::EmptyActions { resource } => {
                write!(f, "the grant of {resource:?} names no action")
            }
            GrantsReason::EmptyAction { resource } => {
                write!(f, "the grant of {resource:?} names an empty action")
            }
            GrantsReason::RepeatedAction { resource, action } => write!(
                f,
                "the grant of {resource:?} names the action {action:?} twice"
            ),
            GrantsReason::DuplicateResource { resource } => {
                write!(f, "the resource {resource:?} is granted twice")
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
/// The file is exactly `{"schema": "wc-009.lab-grants/v3", "label": "lab
/// stand-in, not admission", "grants": [{"resource": "...", "actions":
/// ["..."]}]}`; an empty `grants` list is valid. Each resource is a non-empty
/// string granted once, and its actions a non-empty list of non-empty,
/// distinct strings. The grants come back in file order. The first refusal is
/// the answer, with the path and its own reason.
pub fn read_grants(path: &Path) -> Result<Vec<LabGrant>, GrantsRefusal> {
    let refusal = |reason| GrantsRefusal {
        path: path.to_path_buf(),
        reason,
    };
    let bytes = fs::read(path).map_err(|error| refusal(GrantsReason::Unreadable(error)))?;
    parse_grants(&bytes).map_err(refusal)
}

/// The grants in `bytes`, checked by hand against the one file form: the
/// document, its keys, the schema, the label, then each entry in order.
fn parse_grants(bytes: &[u8]) -> Result<Vec<LabGrant>, GrantsReason> {
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
    let grants = grants_key(document, "grants")?;
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
    let entries = grants.as_array().ok_or(GrantsReason::GrantsNotAList)?;
    let mut granted: Vec<LabGrant> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let grant = checked_grant(index, entry)?;
        if granted.iter().any(|seen| seen.resource == grant.resource) {
            return Err(GrantsReason::DuplicateResource {
                resource: grant.resource,
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

/// The entry at `index`, checked: no retired v2 key, the `capability-request`
/// shape, a non-empty resource, and a non-empty list of non-empty, distinct
/// actions, each refused with its own reason.
fn checked_grant(index: usize, entry: &Value) -> Result<LabGrant, GrantsReason> {
    if let Some(key) = entry.as_object().and_then(|entry| {
        RETIRED_GRANT_KEYS
            .into_iter()
            .find(|key| entry.contains_key(*key))
    }) {
        return Err(GrantsReason::RetiredKey { index, key });
    }
    let grant = grant_entry(entry).ok_or(GrantsReason::EntryNotAGrant { index })?;
    if grant.resource.is_empty() {
        return Err(GrantsReason::EmptyResource { index });
    }
    if grant.actions.is_empty() {
        return Err(GrantsReason::EmptyActions {
            resource: grant.resource,
        });
    }
    if grant.actions.iter().any(String::is_empty) {
        return Err(GrantsReason::EmptyAction {
            resource: grant.resource,
        });
    }
    for (at, action) in grant.actions.iter().enumerate() {
        if grant.actions[..at].contains(action) {
            return Err(GrantsReason::RepeatedAction {
                resource: grant.resource.clone(),
                action: action.clone(),
            });
        }
    }
    Ok(grant)
}

/// One grant: an object of exactly the two keys `resource`, a string, and
/// `actions`, a list of strings. Anything else is no grant.
fn grant_entry(entry: &Value) -> Option<LabGrant> {
    let entry = entry.as_object()?;
    if entry.len() != GRANT_KEYS.len() {
        return None;
    }
    let resource = entry.get(GRANT_KEYS[0])?.as_str()?.to_owned();
    let actions = entry
        .get(GRANT_KEYS[1])?
        .as_array()?
        .iter()
        .map(|action| action.as_str().map(str::to_owned))
        .collect::<Option<Vec<String>>>()?;
    Some(LabGrant { resource, actions })
}
