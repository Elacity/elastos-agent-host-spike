//! Admitting a capsule bundle that is named by the CID of its files.
//!
//! A bundle's name is the CID that `elastos-bundle-identity` computes from
//! its folder. A publisher's signature over that name lives in a file beside
//! the bundle, never inside it. This module holds the checks that signature
//! must pass, the limits under which a bundle and the bundles it pins are
//! walked, which manifests a start by CID takes, and the fixed codes a
//! refusal is reported by. It starts nothing: `Runtime::run_by_bundle` calls
//! these checks in order, for the bundle it was asked for and then for every
//! bundle that one pins.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

use elastos_bundle_identity::{Budget, CheckedBundle, LabCid, Refusal, MANIFEST_FILE};
use elastos_common::{
    CapsuleExecution, CapsuleManifest, CapsuleRole, CapsuleRuntimeAbi, CapsuleType, PinnedManifest,
    PinnedManifestError, ELASTOS_BUS_V1_CONTRACT,
};
use elastos_runtime::signature::SignatureVerifier;
use serde::Deserialize;

// The lab's own refusals (its test signatures, records and platform variants)
// are compiled into `elastos-bundle-identity` only under its `lab` feature.
// Cargo can turn a feature on for a whole build without anyone asking for it
// here, so this crate refuses to build if that has happened.
const _: () = assert!(
    !elastos_bundle_identity::LAB_REFUSALS,
    "elastos-server must not be built with elastos-bundle-identity's `lab` feature"
);

/// Domain of a bundle signature: it is made over the CID text under this.
pub const BUNDLE_SIGNATURE_DOMAIN: &str = "elastos.capsule.bundle.v1";

/// `schema` of the signature file beside a bundle.
pub const BUNDLE_SIGNATURE_SCHEMA: &str = "elastos.capsule.bundle-signature/v1";

/// The most a walk of a bundle may take in, at staging and at every start.
///
/// - Depth 16: the deepest bundle in the tree today is two parts
///   (`images/01.png`); 16 leaves room and keeps the encoder's recursion to
///   16 frames.
/// - 1,024 bytes of path: the smaller of the whole-path limits of the two
///   systems the Runtime runs on, so no bundle that either can hold has a
///   longer one. It is a bound, not a promise: the store's own folder comes
///   before a bundle's path, so a path near the limit can still be too long
///   to write there, and that bundle is then not staged.
/// - 4,096 entries and 64 MiB of file bytes. The walk holds every file byte
///   it reads, and that is its largest holding, so 64 MiB bounds that part.
///   It is not a bound on all the memory a walk takes: the entries' paths
///   and the folder listings come on top (bounded by the entry and path
///   limits: 4,096 paths of at most 1,024 bytes), and so do the blocks the
///   encoder builds to name the files, which grow with the same entries.
///   The largest example bundle today is under 1 MiB.
pub const BUNDLE_WALK_BUDGET: Budget = Budget {
    max_entries: 4_096,
    max_total_bytes: 64 * 1024 * 1024,
    max_depth: 16,
    max_path_bytes: 1_024,
};

/// The most bundles one start by CID takes in: the one asked for and every
/// bundle pinned below it, each counted every time a pin reaches it.
pub const CLOSURE_MAX_MEMBERS: usize = 16;

/// How far below the bundle asked for a pin may reach. That bundle is at
/// depth 1 and the bundles it pins at depth 2.
pub const CLOSURE_MAX_DEPTH: usize = 4;

/// Why a bundle was not admitted. Each has one fixed code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleRefusal {
    /// There is no signature file beside the bundle.
    Unsigned,
    /// The Home trusts no key, so no signature can be accepted.
    TrustSetEmpty,
    /// The signature file is not the one shape it may have.
    SignatureUnparsed(String),
    /// The signature file is for another bundle.
    SignatureNamesAnotherCid { file: String, computed: String },
    /// The signer is not a canonical key, or the signature does not verify,
    /// or the key that verified it is not trusted. One refusal for all
    /// three, with no detail, so that the answer does not say which.
    SignatureNotAccepted,
    /// The walk of the bundle's folder refused it.
    Walk { code: &'static str, detail: String },
    /// The store's slot for this CID holds something that is not this bundle.
    SlotDiffers { cid: String, found: String },
    /// The store could not be read or written.
    Store(String),
    /// The text given as a bundle's CID is not one.
    CidFormInvalid(String),
    /// The store has no slot for this CID. A start by CID fetches nothing.
    Missing(String),
    /// The slot's files do not recompute to the CID that was asked for.
    CidMismatch { asked: String, computed: String },
    /// The bundle's manifest has a key a start by CID does not take.
    ManifestFieldRefused(String),
    /// The Runtime's manifest type refuses the bundle's manifest, or its
    /// entrypoint is not one of the bundle's files.
    ManifestInvalid(String),
    /// The bundle is not an app component of the one contract this start runs.
    NotAComponent(String),
    /// The admitted component could not be compiled or started, or it ended
    /// in an error. Everything before this passed.
    StartFailed(String),
    /// A requirement's name has a character outside letters, digits, `.`,
    /// `_` and `-`, or is `.` or `..`.
    RequirementNameInvalid(String),
    /// A requirement carries no pin. A start by CID takes a manifest's
    /// requirements only when each names its bundle by CID.
    RequirementUnpinned(String),
    /// The bundle staged under a pin is called something else than the
    /// requirement that pins it. The text is the name the bundle carries.
    RequirementMismatch(String),
    /// A pin sits deeper than [`CLOSURE_MAX_DEPTH`].
    ClosureTooDeep,
    /// A pin reaches one bundle more than [`CLOSURE_MAX_MEMBERS`].
    ClosureTooMany,
    /// A pinned bundle was refused: the name of the requirement that pins
    /// it, and the refusal, which keeps its own code.
    Requirement {
        name: String,
        refusal: Box<BundleRefusal>,
    },
}

impl BundleRefusal {
    /// The fixed code of this refusal.
    pub fn code(&self) -> &'static str {
        match self {
            BundleRefusal::Unsigned => "bundle_unsigned",
            BundleRefusal::TrustSetEmpty => "bundle_trust_set_empty",
            BundleRefusal::SignatureUnparsed(_) => "bundle_signature_unparsed",
            BundleRefusal::SignatureNamesAnotherCid { .. } => "bundle_signature_names_another_cid",
            BundleRefusal::SignatureNotAccepted => "bundle_signature_not_accepted",
            BundleRefusal::Walk { code, .. } => code,
            BundleRefusal::SlotDiffers { .. } => "bundle_slot_differs",
            BundleRefusal::Store(_) => "bundle_store_io",
            BundleRefusal::CidFormInvalid(_) => "bundle_cid_form_invalid",
            BundleRefusal::Missing(_) => "bundle_missing",
            BundleRefusal::CidMismatch { .. } => "bundle_cid_mismatch",
            BundleRefusal::ManifestFieldRefused(_) => "bundle_manifest_field_refused",
            BundleRefusal::ManifestInvalid(_) => "bundle_manifest_invalid",
            BundleRefusal::NotAComponent(_) => "bundle_not_a_component",
            BundleRefusal::StartFailed(_) => "bundle_start_failed",
            BundleRefusal::RequirementNameInvalid(_) => "bundle_requirement_name_invalid",
            BundleRefusal::RequirementUnpinned(_) => "bundle_requirement_unpinned",
            BundleRefusal::RequirementMismatch(_) => "bundle_requirement_mismatch",
            BundleRefusal::ClosureTooDeep => "bundle_closure_too_deep",
            BundleRefusal::ClosureTooMany => "bundle_closure_too_many",
            BundleRefusal::Requirement { refusal, .. } => refusal.code(),
        }
    }
}

impl fmt::Display for BundleRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            BundleRefusal::Unsigned => write!(f, "{code}: no signature file beside the bundle"),
            BundleRefusal::TrustSetEmpty => write!(f, "{code}: this Home trusts no signing key"),
            BundleRefusal::SignatureUnparsed(why) => write!(f, "{code}: {why}"),
            BundleRefusal::SignatureNamesAnotherCid { file, computed } => write!(
                f,
                "{code}: the signature file names {file}, the bundle is {computed}"
            ),
            BundleRefusal::SignatureNotAccepted => {
                write!(f, "{code}: the bundle's signature is not accepted")
            }
            BundleRefusal::Walk { detail, .. } => write!(f, "{code}: {detail}"),
            BundleRefusal::SlotDiffers { cid, found } => write!(
                f,
                "{code}: the store's slot for {cid} does not hold that bundle: {found}"
            ),
            BundleRefusal::Store(why) => write!(f, "{code}: {why}"),
            BundleRefusal::CidFormInvalid(text) => {
                write!(f, "{code}: {text:?} is not a bundle's CID")
            }
            BundleRefusal::Missing(cid) => {
                write!(f, "{code}: this Home's store holds no bundle {cid}")
            }
            BundleRefusal::CidMismatch { asked, computed } => write!(
                f,
                "{code}: the store's slot for {asked} holds files that are {computed}"
            ),
            BundleRefusal::ManifestFieldRefused(key) => write!(f, "{code}: {key}"),
            BundleRefusal::ManifestInvalid(why) => write!(f, "{code}: {why}"),
            BundleRefusal::NotAComponent(why) => write!(f, "{code}: {why}"),
            BundleRefusal::StartFailed(why) => write!(f, "{code}: {why}"),
            BundleRefusal::RequirementNameInvalid(name) => write!(f, "{code}: {name:?}"),
            BundleRefusal::RequirementUnpinned(name) => write!(f, "{code}: {name}"),
            BundleRefusal::RequirementMismatch(found) => {
                write!(
                    f,
                    "{code}: the bundle staged under the pin is called {found:?}"
                )
            }
            BundleRefusal::ClosureTooDeep => {
                write!(f, "{code}: a pin sits below depth {CLOSURE_MAX_DEPTH}")
            }
            BundleRefusal::ClosureTooMany => {
                write!(f, "{code}: more than {CLOSURE_MAX_MEMBERS} bundles")
            }
            // The inner refusal's text begins with the code they share.
            BundleRefusal::Requirement { name, refusal } => {
                write!(f, "{refusal} (requirement {name})")
            }
        }
    }
}

impl std::error::Error for BundleRefusal {}

/// The most that is read of a signature file. One is about 300 bytes.
pub const MAX_SIGNATURE_FILE_BYTES: u64 = 4_096;

/// Where the Home at `data_dir` keeps the files of the bundle `cid`.
pub fn bundle_slot(data_dir: &Path, cid: &LabCid) -> PathBuf {
    by_cid(data_dir).join(cid.to_string())
}

/// Where the Home at `data_dir` keeps the signature over `cid`: beside the
/// bundle's folder, never inside it.
pub fn bundle_signature_path(data_dir: &Path, cid: &LabCid) -> PathBuf {
    by_cid(data_dir).join(format!("{cid}.sig.json"))
}

fn by_cid(data_dir: &Path) -> PathBuf {
    data_dir.join("capsules").join("by-cid")
}

/// Read a signature file of at most [`MAX_SIGNATURE_FILE_BYTES`]. The read
/// takes one byte more than that, which is how it learns that a file is over
/// the cap; no more of such a file is read. Only [`check_bundle_signature`]
/// calls this, at its place in the order.
fn read_signature_file(path: &Path) -> Result<Vec<u8>, BundleRefusal> {
    let unread = |error: std::io::Error| {
        BundleRefusal::SignatureUnparsed(format!("could not read the signature file: {error}"))
    };
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        // It was there a moment ago, when the check began.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(BundleRefusal::Unsigned)
        }
        Err(error) => return Err(unread(error)),
    };
    let mut bytes = Vec::new();
    file.take(MAX_SIGNATURE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(unread)?;
    if bytes.len() as u64 > MAX_SIGNATURE_FILE_BYTES {
        return Err(BundleRefusal::SignatureUnparsed(format!(
            "the signature file is over {MAX_SIGNATURE_FILE_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// The signature file beside a bundle, exactly: no other key is allowed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleSignatureFile {
    schema: String,
    cid: String,
    signer_did: String,
    signature: String,
}

/// A signature file that passed [`check_bundle_signature`]: who signed, and
/// the file's bytes as that check read them, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSignature {
    pub signer_did: String,
    pub file: Vec<u8>,
}

/// Check the signature file at `file` for the bundle the Runtime computed
/// `cid` for, against the keys `verifier` trusts. Returns the signer's
/// `did:key` and the bytes that were checked.
///
/// The order is fixed: the file exists; the Home trusts at least one key;
/// only then is the file read (up to [`MAX_SIGNATURE_FILE_BYTES`] and one
/// byte more, to tell a file over the cap), and it parses and names this CID;
/// the signer is one canonical Ed25519
/// `did:key`; the signature verifies strictly for that key over the CID text;
/// and only then, that key is one the Home trusts. There is no `dev_mode`
/// here: a bundle named by CID is never admitted unsigned.
///
/// The key in the file is a claim by whoever wrote the file. Trust is asked
/// only of a key that has already verified the signature, and this is the
/// one place in the server that asks it.
///
/// NOT EQUALISED: TIME. The three ways the last three steps fail give one
/// refusal with one detail and one log line, but they do not take the same
/// time: trust adds a list scan, and the signature and key checks keep
/// caches of what passed (`crypto.rs`, `elastos-identity/src/store.rs`). The
/// only caller today is a person running a command, one process per attempt,
/// on a file they supplied. BEFORE ANY ROUTE LETS A REMOTE CALLER REACH THIS
/// FUNCTION, ITS TIME MUST BE MADE THE SAME FOR THOSE THREE.
pub fn check_bundle_signature(
    file: &Path,
    cid: &LabCid,
    verifier: &SignatureVerifier,
) -> Result<AcceptedSignature, BundleRefusal> {
    let missing = |error: &std::io::Error| error.kind() == std::io::ErrorKind::NotFound;
    if matches!(std::fs::metadata(file), Err(error) if missing(&error)) {
        return Err(BundleRefusal::Unsigned);
    }
    if verifier.trusted_key_count() == 0 {
        return Err(BundleRefusal::TrustSetEmpty);
    }
    let bytes = read_signature_file(file)?;
    let parsed: BundleSignatureFile = serde_json::from_slice(&bytes)
        .map_err(|error| BundleRefusal::SignatureUnparsed(error.to_string()))?;
    if parsed.schema != BUNDLE_SIGNATURE_SCHEMA {
        return Err(BundleRefusal::SignatureUnparsed(format!(
            "schema is not {BUNDLE_SIGNATURE_SCHEMA}"
        )));
    }
    // One spelling of a signature: lower-case hex, as `sign-payload` prints it.
    let lower_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    if parsed.signature.len() != 128 || !parsed.signature.bytes().all(lower_hex) {
        return Err(BundleRefusal::SignatureUnparsed(
            "signature is not 128 lower-case hex characters".into(),
        ));
    }
    let computed = cid.to_string();
    if parsed.cid != computed {
        return Err(BundleRefusal::SignatureNamesAnotherCid {
            file: parsed.cid,
            computed,
        });
    }
    let Ok(key) = crate::crypto::decode_did_key(&parsed.signer_did) else {
        return Err(not_accepted(&computed));
    };
    if crate::crypto::verify_domain_separated_signature(
        &parsed.signer_did,
        BUNDLE_SIGNATURE_DOMAIN,
        computed.as_bytes(),
        &parsed.signature,
    )
    .is_err()
    {
        return Err(not_accepted(&computed));
    }
    if !verifier.trusts(&key) {
        return Err(not_accepted(&computed));
    }
    Ok(AcceptedSignature {
        signer_did: parsed.signer_did,
        file: bytes,
    })
}

/// The one refusal, and the one log line, for a signer that is not a
/// canonical key, a signature that does not verify, and a key that is not
/// trusted. It says nothing that tells them apart.
fn not_accepted(cid: &str) -> BundleRefusal {
    tracing::warn!("bundle {cid}: signature not accepted");
    BundleRefusal::SignatureNotAccepted
}

/// The code and detail for a refusal of the walk. Every variant is named:
/// a refusal added to the crate later does not compile here until it has a
/// code. The lab's own refusals are not among them, because they do not
/// exist in this build (see the assertion at the top of this file).
pub fn walk_refusal(refusal: Refusal) -> BundleRefusal {
    let code = match &refusal {
        Refusal::NoManifest => "bundle_walk_no_manifest",
        Refusal::ManifestUnparsed(_) => "bundle_walk_manifest_unparsed",
        Refusal::ManifestInvalid(_) => "bundle_walk_manifest_invalid",
        Refusal::NotRegularFile { .. } => "bundle_walk_not_regular_file",
        Refusal::NonUtf8Name { .. } => "bundle_walk_non_utf8_name",
        Refusal::DuplicatePath { .. } => "bundle_walk_duplicate_path",
        Refusal::BadPathPart { .. } => "bundle_walk_bad_path_part",
        Refusal::FileAndDirectory { .. } => "bundle_walk_file_and_directory",
        Refusal::FileOverChunkLimit { .. } => "bundle_walk_file_over_chunk_limit",
        Refusal::FileOverLeafLimit { .. } => "bundle_walk_file_over_leaf_limit",
        Refusal::DirectoryOverBlockLimit { .. } => "bundle_walk_directory_over_block_limit",
        Refusal::Changed { .. } => "bundle_walk_changed",
        Refusal::Unreadable { .. } => "bundle_walk_unreadable",
        Refusal::OverBudget { .. } => "bundle_walk_over_budget",
        Refusal::PinRefused { .. } => "bundle_walk_pin_refused",
        Refusal::NotALabCid { .. } => "bundle_walk_not_a_cid",
        Refusal::NameMismatch { .. } => "bundle_walk_name_mismatch",
    };
    BundleRefusal::Walk {
        code,
        detail: refusal.to_string(),
    }
}

/// The keys of `capsule.json` that a start by CID takes. It is a closed
/// list: a key that is not on it is refused by name, whatever its value, so
/// a key the manifest format gains later is refused until this list names it.
///
/// Not on it, on purpose: `agent`, `capabilities`, `permissions`,
/// `provides`, `providers`, `authority`, `interfaces`, `microvm`, `viewer`,
/// `model_content` and `signature`. Each is, or carries, an authority or a
/// relation to another capsule, and a field would be admitted without the
/// code that gives it meaning. So the one authority field this start takes
/// is `asks`, and what starts has its asks as its ceiling, or an empty one.
pub const BUNDLE_MANIFEST_KEYS: [&str; 18] = [
    // What it is called.
    "schema",
    "name",
    "version",
    "description",
    "author",
    // What kind of capsule it is. [`admit_bundle_manifest`] holds each to the
    // one value this start runs.
    "role",
    "type",
    "execution",
    "runtime_abi",
    "bus_contract",
    "wit_world_sha256",
    "entrypoint",
    // Presentation. Home reads these; a start from the command line makes no
    // window and registers no projection.
    "projections",
    "window_policy",
    "icon",
    // What the capsule says it wants as limits; never an authority. On this
    // path nothing reads it: the component provider applies its own fixed
    // limits to every component.
    "resources",
    // The bundles this one needs, each named by CID: [`admit_bundle_manifest`]
    // refuses a requirement without a pin, and the start then holds every
    // pinned bundle to the checks it holds this one to. It is a condition on
    // the start and gives the capsule nothing: it adds nothing to its
    // ceiling, no grant is made, and it has no way to reach a pinned bundle
    // or its bytes.
    "requires",
    // The most this capsule may ever ask the Runtime for: each a resource
    // and its actions. They are its whole ceiling, held by the bridge. They
    // grant nothing: a request inside them is still put to the shell. The
    // manifest type's own rules for asks hold here as everywhere. A capsule
    // whose manifest has none is started sealed and can ask for nothing.
    "asks",
];

/// The manifest and the component of a bundle that a start by CID may run.
#[derive(Debug, Clone)]
pub struct AdmittedBundle {
    pub manifest: CapsuleManifest,
    /// The entrypoint's bytes as the walk read them.
    pub component: Vec<u8>,
    /// The bundles the manifest pins: requirement name and CID text, in the
    /// manifest's order. Every requirement of the manifest is one of them.
    pub pins: Vec<(String, String)>,
}

/// Decide, from the walked bytes alone, whether a start by CID takes this
/// bundle's manifest. The order: every key as written is on
/// [`BUNDLE_MANIFEST_KEYS`], before the manifest is parsed as a type; the
/// Runtime's reader of a manifest that may pin checks the pins and gives
/// them; here, and nowhere else in the server, the pins are then taken off
/// and the ordinary manifest type parses and validates what is left, so the
/// manifest that can start exists only beside its pins, in the value this
/// returns; it is an app component of the one contract; its entrypoint is
/// one of the walked files; every requirement has a plain name and a pin.
/// Nothing is read from disk here. The start calls this only for a bundle
/// whose files recomputed to the CID asked for and whose signature was
/// accepted. (The walk before it has already parsed and validated the same
/// bytes once, with that same reader, for the bundle's name and the form of
/// its pins: see `Runtime::run_by_bundle`'s per-bundle checks.)
pub fn admit_bundle_manifest(bundle: &CheckedBundle) -> Result<AdmittedBundle, BundleRefusal> {
    let invalid = BundleRefusal::ManifestInvalid;
    let bytes = bundle
        .entry(MANIFEST_FILE)
        .ok_or_else(|| invalid(format!("the bundle has no {MANIFEST_FILE}")))?;
    let keys: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
    if let Some(key) = keys
        .keys()
        .find(|key| !BUNDLE_MANIFEST_KEYS.contains(&key.as_str()))
    {
        return Err(BundleRefusal::ManifestFieldRefused(key.clone()));
    }
    // The Runtime's one reader of pins judges them; it hands out no manifest.
    let pins = PinnedManifest::parse(bytes)
        .map_err(|error| match error {
            PinnedManifestError::Unparsed(why) | PinnedManifestError::Invalid(why) => invalid(why),
            PinnedManifestError::Pin { code, requirement } => {
                invalid(format!("{code}: requirement {requirement:?}"))
            }
        })?
        .pins()
        .to_vec();
    // The manifest that can start is read here, from the same bytes, by the
    // ordinary type, which refuses a pin: so the pins, which that reader
    // has checked and `pins` now holds, are taken off first. Without a pin
    // the bytes are read as they are.
    let manifest: CapsuleManifest = if pins.is_empty() {
        serde_json::from_slice(bytes)
    } else {
        let mut unpinned: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        let requires = unpinned
            .get_mut("requires")
            .and_then(|it| it.as_array_mut());
        for requirement in requires.into_iter().flatten() {
            if let Some(requirement) = requirement.as_object_mut() {
                requirement.remove("cid");
            }
        }
        serde_json::from_value(unpinned)
    }
    .map_err(|error| invalid(error.to_string()))?;
    manifest.validate().map_err(invalid)?;
    let component_of_the_contract = manifest.role == CapsuleRole::App
        && manifest.capsule_type == CapsuleType::Wasm
        && manifest.runtime_abi == Some(CapsuleRuntimeAbi::ElastosComponentV1)
        && matches!(manifest.execution, None | Some(CapsuleExecution::Component))
        && matches!(
            manifest.bus_contract.as_deref(),
            None | Some(ELASTOS_BUS_V1_CONTRACT)
        );
    if !component_of_the_contract {
        return Err(BundleRefusal::NotAComponent(format!(
            "role {}, type {:?}, runtime_abi {:?}, execution {:?}, bus_contract {:?}",
            manifest.role.as_str(),
            manifest.capsule_type,
            manifest.runtime_abi,
            manifest.execution,
            manifest.bus_contract
        )));
    }
    let component = bundle.entry(&manifest.entrypoint).ok_or_else(|| {
        invalid(format!(
            "entrypoint {:?} is not a file of the bundle",
            manifest.entrypoint
        ))
    })?;
    let plain = |name: &str| {
        let plain_byte = |byte: u8| byte.is_ascii_alphanumeric() || b"._-".contains(&byte);
        !matches!(name, "" | "." | "..") && name.bytes().all(plain_byte)
    };
    if let Some(odd) = manifest.requires.iter().find(|it| !plain(&it.name)) {
        return Err(BundleRefusal::RequirementNameInvalid(odd.name.clone()));
    }
    let pinned = |name: &str| pins.iter().any(|(pin, _)| pin == name);
    if let Some(loose) = manifest.requires.iter().find(|it| !pinned(&it.name)) {
        return Err(BundleRefusal::RequirementUnpinned(loose.name.clone()));
    }
    Ok(AdmittedBundle {
        component: component.to_vec(),
        manifest,
        pins,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use sha2::{Digest, Sha256};

    /// A CID recorded by the lab for one of its fixtures (`web-app`); the
    /// tests here need a well-formed CID, not that bundle.
    pub(crate) const CID_A: &str = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
    /// Another of the lab's recorded CIDs (`agent-host`).
    pub(crate) const CID_B: &str = "bafybeicesxlwcolv5hifwotsyafyyaclaq23gyzwl7esuvhwlownrhatym";

    pub(crate) fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn did(key: &VerifyingKey) -> String {
        crate::crypto::encode_did_key(key).expect("did:key")
    }

    /// A signature made here by hand, not by the server's signer: the
    /// SHA-256 of the domain, one zero byte and the payload, signed.
    pub(crate) fn sign_by_hand(key: &SigningKey, domain: &str, payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(domain.as_bytes());
        hasher.update([0u8]);
        hasher.update(payload.as_bytes());
        hex::encode(key.sign(&hasher.finalize()).to_bytes())
    }

    pub(crate) fn file_for(cid: &str, signer: &str, signature: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": BUNDLE_SIGNATURE_SCHEMA,
            "cid": cid,
            "signer_did": signer,
            "signature": signature,
        }))
        .expect("json")
    }

    pub(crate) fn signed(cid: &str, key: &SigningKey) -> Vec<u8> {
        file_for(
            cid,
            &did(&key.verifying_key()),
            &sign_by_hand(key, BUNDLE_SIGNATURE_DOMAIN, cid),
        )
    }

    fn trusting(keys: &[&SigningKey]) -> SignatureVerifier {
        let mut verifier = SignatureVerifier::new();
        for key in keys {
            verifier.add_trusted_key(key.verifying_key()).expect("key");
        }
        verifier
    }

    fn cid(text: &str) -> LabCid {
        text.parse().expect("a recorded CID")
    }

    /// The check on a file that holds `file`, or on a path where no file is;
    /// its answer's signer. The bytes it hands back are the file's.
    fn check(
        file: Option<&[u8]>,
        cid_text: &str,
        verifier: &SignatureVerifier,
    ) -> Result<String, BundleRefusal> {
        let folder = tempfile::tempdir().expect("a folder");
        let path = folder.path().join("offered.sig.json");
        if let Some(bytes) = file {
            std::fs::write(&path, bytes).expect("write the signature file");
        }
        let accepted = check_bundle_signature(&path, &cid(cid_text), verifier)?;
        assert_eq!(Some(accepted.file.as_slice()), file);
        Ok(accepted.signer_did)
    }

    #[test]
    fn an_empty_trust_set_refuses_before_a_byte_of_the_file_is_read() {
        let publisher = key(1);
        let (empty, trusts) = (trusting(&[]), trusting(&[&publisher]));
        // A valid signature file, padded with spaces to one byte over the cap.
        let mut over = signed(CID_A, &publisher);
        over.resize(MAX_SIGNATURE_FILE_BYTES as usize + 1, b' ');
        assert_eq!(
            check(Some(&over), CID_A, &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        // With a trusted key the same file is refused for its size, and one
        // byte shorter it is accepted: so the size was the file's only fault.
        let refusal = check(Some(&over), CID_A, &trusts).expect_err("over the cap");
        assert_eq!(
            refusal.to_string(),
            "bundle_signature_unparsed: the signature file is over 4096 bytes"
        );
        over.pop();
        assert!(check(Some(&over), CID_A, &trusts).is_ok());

        // A folder where the file should be cannot be read at all. With no
        // trusted key that is never found out.
        let folder = tempfile::tempdir().expect("a folder");
        assert_eq!(
            check_bundle_signature(folder.path(), &cid(CID_A), &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        let refusal = check_bundle_signature(folder.path(), &cid(CID_A), &trusts)
            .expect_err("a folder is not a signature file");
        assert_eq!(refusal.code(), "bundle_signature_unparsed", "{refusal}");

        // And in the source: the read comes after the trust set is asked.
        let code = production();
        let body = &code[code
            .find("pub fn check_bundle_signature(")
            .expect("the check")..];
        let asked = body
            .find("trusted_key_count() == 0")
            .expect("the trust set");
        let read = body.find("read_signature_file(file)").expect("the read");
        assert!(
            asked < read,
            "the file is read before the trust set is asked"
        );
        assert_eq!(code.matches("read_signature_file(").count(), 2, "one call");
    }

    #[test]
    fn a_trusted_publishers_signature_over_the_cid_is_accepted_and_names_the_signer() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher, &key(2)]);
        assert_eq!(
            check(Some(&signed(CID_A, &publisher)), CID_A, &verifier),
            Ok(did(&publisher.verifying_key()))
        );
    }

    #[test]
    fn a_missing_file_is_unsigned_whatever_the_trust_set_holds() {
        assert_eq!(
            check(None, CID_A, &trusting(&[&key(1)])),
            Err(BundleRefusal::Unsigned)
        );
        assert_eq!(
            check(None, CID_A, &trusting(&[])),
            Err(BundleRefusal::Unsigned)
        );
        assert_eq!(BundleRefusal::Unsigned.code(), "bundle_unsigned");
    }

    #[test]
    fn an_empty_trust_set_refuses_before_the_file_is_parsed() {
        let publisher = key(1);
        let empty = trusting(&[]);
        assert_eq!(
            check(Some(&signed(CID_A, &publisher)), CID_A, &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        // A file that does not even parse gets the same answer, so the trust
        // set is asked first.
        assert_eq!(
            check(Some(b"not json"), CID_A, &empty),
            Err(BundleRefusal::TrustSetEmpty)
        );
        assert_eq!(
            BundleRefusal::TrustSetEmpty.code(),
            "bundle_trust_set_empty"
        );
    }

    #[test]
    fn a_file_of_another_shape_is_unparsed() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        let signer = did(&publisher.verifying_key());
        let signature = sign_by_hand(&publisher, BUNDLE_SIGNATURE_DOMAIN, CID_A);
        let unknown_key = serde_json::to_vec(&serde_json::json!({
            "schema": BUNDLE_SIGNATURE_SCHEMA, "cid": CID_A, "signer_did": signer,
            "signature": signature, "note": "x",
        }))
        .unwrap();
        let other_schema = serde_json::to_vec(&serde_json::json!({
            "schema": "elastos.capsule.bundle-signature/v2", "cid": CID_A,
            "signer_did": signer, "signature": signature,
        }))
        .unwrap();
        let short = file_for(CID_A, &signer, &signature[..127]);
        // The same signature in capitals: a second spelling, refused.
        let capitals = file_for(CID_A, &signer, &signature.to_uppercase());
        assert_ne!(signature.to_uppercase(), signature);
        // A key written twice, with the same value both times.
        let twice = String::from_utf8(file_for(CID_A, &signer, &signature))
            .unwrap()
            .replacen('{', &format!("{{\"cid\":\"{CID_A}\","), 1)
            .into_bytes();
        let not_hex = file_for(CID_A, &signer, &format!("{}g", &signature[..127]));
        let repeated = check(Some(&twice), CID_A, &verifier).expect_err("a repeated key");
        assert!(
            repeated.to_string().contains("duplicate field `cid`"),
            "{repeated}"
        );
        for (case, file) in [
            ("unknown key", unknown_key),
            ("other schema", other_schema),
            ("127 characters", short),
            ("not hex", not_hex),
            ("capitals", capitals),
            ("a repeated key", twice),
            ("not json", b"{".to_vec()),
        ] {
            let refusal = check(Some(&file), CID_A, &verifier).expect_err(case);
            assert_eq!(
                refusal.code(),
                "bundle_signature_unparsed",
                "{case}: {refusal}"
            );
        }
    }

    #[test]
    fn a_valid_signature_file_for_another_bundle_is_refused_by_that_code() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        // Valid for A in every way; offered for B.
        let refusal = check(Some(&signed(CID_A, &publisher)), CID_B, &verifier).expect_err("for A");
        assert_eq!(
            refusal,
            BundleRefusal::SignatureNamesAnotherCid {
                file: CID_A.into(),
                computed: CID_B.into()
            }
        );
        assert_eq!(refusal.code(), "bundle_signature_names_another_cid");
    }

    #[test]
    fn a_signature_under_another_domain_is_not_accepted() {
        let publisher = key(1);
        let verifier = trusting(&[&publisher]);
        let other_domain = file_for(
            CID_A,
            &did(&publisher.verifying_key()),
            &sign_by_hand(&publisher, "elastos.capsule.record.v1", CID_A),
        );
        assert_eq!(
            check(Some(&other_domain), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
    }

    #[test]
    fn a_trusted_key_named_beside_a_signature_that_does_not_verify_is_not_accepted() {
        // The file names a key the Home trusts. The signature was made by
        // another key. Trust in the name must not admit it.
        let trusted = key(1);
        let verifier = trusting(&[&trusted]);
        let forged = file_for(
            CID_A,
            &did(&trusted.verifying_key()),
            &sign_by_hand(&key(9), BUNDLE_SIGNATURE_DOMAIN, CID_A),
        );
        assert_eq!(
            check(Some(&forged), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
    }

    #[test]
    fn a_valid_signature_by_a_key_that_is_not_trusted_is_not_accepted() {
        let stranger = key(7);
        let verifier = trusting(&[&key(1)]);
        assert_eq!(
            check(Some(&signed(CID_A, &stranger)), CID_A, &verifier),
            Err(BundleRefusal::SignatureNotAccepted)
        );
        // The control: the same file is accepted once that key is trusted.
        assert!(check(
            Some(&signed(CID_A, &stranger)),
            CID_A,
            &trusting(&[&stranger])
        )
        .is_ok());
    }

    #[test]
    fn a_bad_signer_a_bad_signature_and_an_untrusted_key_get_one_identical_refusal() {
        let trusted = key(1);
        let verifier = trusting(&[&trusted]);
        let signature = sign_by_hand(&trusted, BUNDLE_SIGNATURE_DOMAIN, CID_A);
        let bad_signer = file_for(CID_A, "did:web:example.org", &signature);
        let bad_signature = file_for(
            CID_A,
            &did(&trusted.verifying_key()),
            &sign_by_hand(&key(9), BUNDLE_SIGNATURE_DOMAIN, CID_A),
        );
        let untrusted = signed(CID_A, &key(7));
        let refusals: Vec<BundleRefusal> = [bad_signer, bad_signature, untrusted]
            .iter()
            .map(|file| check(Some(file), CID_A, &verifier).expect_err("not accepted"))
            .collect();
        for refusal in &refusals {
            assert_eq!(refusal, &refusals[0]);
            assert_eq!(refusal.to_string(), refusals[0].to_string());
            assert_eq!(refusal.code(), "bundle_signature_not_accepted");
        }
        assert_eq!(
            refusals[0].to_string(),
            "bundle_signature_not_accepted: the bundle's signature is not accepted"
        );
    }

    /// This file's code without its tests.
    fn production() -> &'static str {
        let source = include_str!("bundle_admission.rs");
        &source[..source.find("#[cfg(test)]").expect("the tests module")]
    }

    #[test]
    fn trust_is_asked_once_in_the_server_and_only_after_the_signature_verified() {
        let code = production();
        assert_eq!(
            code.matches(".trusts(").count(),
            1,
            "one call site in this file"
        );
        let verify = code
            .find("verify_domain_separated_signature(")
            .expect("the verify call");
        let trusts = code.find(".trusts(").expect("the trust question");
        assert!(
            verify < trusts,
            "trust is asked before the signature is verified"
        );
        // The three refusals share one maker, which holds the one log line.
        assert_eq!(code.matches("Err(not_accepted(&computed))").count(), 3);
        assert_eq!(code.matches("tracing::").count(), 1, "one log line");
        // Outside its comments this file never names `dev_mode`: the check
        // takes no such input, so no setting can relax it.
        let named: Vec<&str> = code
            .lines()
            .filter(|line| !line.trim_start().starts_with("//") && line.contains("dev_mode"))
            .collect();
        assert!(named.is_empty(), "dev_mode named in code: {named:?}");

        // No other file of the server asks the question.
        fn rust_files(dir: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
            for item in std::fs::read_dir(dir).expect("list") {
                let path = item.expect("entry").path();
                if path.is_dir() {
                    rust_files(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    found.push(path);
                }
            }
        }
        let mut files = Vec::new();
        rust_files(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        assert!(
            files.len() > 50,
            "the walk of the server's sources found {} files",
            files.len()
        );
        let askers: Vec<String> = files
            .iter()
            .filter(|path| {
                std::fs::read_to_string(path)
                    .expect("read")
                    .contains(".trusts(")
            })
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            askers,
            ["bundle_admission.rs"],
            "who asks whether a key is trusted"
        );
    }

    #[test]
    fn the_server_does_not_build_with_the_labs_refusals() {
        // The assertion itself cannot be run as a test: with the feature on
        // this crate does not compile. This holds that it is still here, in
        // the code and not under a test cfg.
        let code = production();
        assert!(
            code.contains("const _: () = assert!(\n    !elastos_bundle_identity::LAB_REFUSALS,")
        );
    }

    #[test]
    fn a_walk_refusal_keeps_its_own_name_and_text() {
        let refusal = walk_refusal(Refusal::OverBudget {
            limit: "depth",
            path: "a/b".into(),
        });
        assert_eq!(refusal.code(), "bundle_walk_over_budget");
        assert_eq!(
            refusal.to_string(),
            "bundle_walk_over_budget: a/b passes the walk's limit on depth"
        );
        assert_eq!(
            walk_refusal(Refusal::NoManifest).code(),
            "bundle_walk_no_manifest"
        );
        let refusal = walk_refusal(Refusal::PinRefused {
            code: "pin_form_invalid",
            requirement: "content".into(),
        });
        assert_eq!(refusal.code(), "bundle_walk_pin_refused");
        assert_eq!(
            refusal.to_string(),
            "bundle_walk_pin_refused: the Runtime refuses the pinned manifest capsule.json (pin_form_invalid): requirement \"content\""
        );
    }

    #[test]
    fn the_walk_budget_is_the_four_numbers_the_design_gives() {
        assert_eq!(
            BUNDLE_WALK_BUDGET,
            Budget {
                max_entries: 4_096,
                max_total_bytes: 67_108_864,
                max_depth: 16,
                max_path_bytes: 1_024,
            }
        );
    }
}
