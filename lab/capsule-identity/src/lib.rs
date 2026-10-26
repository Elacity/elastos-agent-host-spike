//! Lab capsule identity: one deterministic **lab CID** over a whole capsule
//! bundle (PRINCIPLES 13 and 15).
//!
//! This crate answers two questions: "do these bytes match this name?" and
//! "did this test key sign this lab CID?". It never answers "may this run?":
//! it makes no trust, admission or launch decision and sits in no admission
//! or launch path. Its value is a lab CID,
//! printed `lab-cid:sha256:<64 lowercase hex>`. It is not the Runtime's CID:
//! the Runtime names a published capsule by the CID its IPFS provider returns
//! for the capsule archive, and this crate does not reproduce that rule.
//!
//! # The encoding
//!
//! The lab CID is SHA-256 over one byte stream:
//!
//! 1. the framing tag `lab.capsule-identity.bundle/v1\n` ([`FRAMING_TAG`]);
//! 2. then, for every regular file under the bundle root, sorted by its
//!    bundle-relative, `/`-separated UTF-8 path in byte order: the path
//!    length as u64 big-endian, the path bytes, the content length as u64
//!    big-endian, the content bytes.
//!
//! Directories add nothing themselves. Nothing else enters the stream: no
//! folder name, absolute path, mtime, mode or owner. The digest prints as
//! `lab-cid:sha256:` and 64 lowercase hex characters.
//!
//! # One naming path
//!
//! [`checked_bundle`] walks a bundle, checks its root manifest, and hands its
//! entries to [`encode_entries`], the encoder. Together the walk and the
//! encoder are the only code that names a bundle; tests and tools call them
//! and re-implement neither. [`lab_cid`] is the same walk and returns only
//! its lab CID. [`check_name`] checks a claimed name, such as one a URL or a
//! Store row gives, by recomputing the name with [`lab_cid`]: it computes no
//! name of its own. [`CheckedBundle::check_name`] is its checked form: the
//! same claim check and the same compare, on the lab CID a checked bundle
//! holds. [`lab_cid`] is [`lab_cid_observed`] with an observer that does
//! nothing, and [`lab_cid_observed`] is [`checked_bundle_observed`]'s lab
//! CID, so there is one walk; tests watch it at two [`Moment`]s to change a
//! bundle while it is named. The walk's two checks, [`entry_kind`] and
//! [`entry_path`], are public only so tests can give them what a test folder
//! cannot hold: a device, or a name that is not UTF-8.
//!
//! # The checked bundle
//!
//! A caller that must use the bytes a name covers, to audit, stage or sign
//! them, takes them from the [`CheckedBundle`] the walk returns, never from a
//! second read of the folder: a file changed between two reads would be used
//! under a name that does not cover it. The value's fields are private, so
//! its lab CID always names its entries. It holds a name and bytes, never a
//! decision.
//!
//! # Test-key publisher signature
//!
//! [`sign_bundle`] signs the printed lab CID from [`lab_cid`]. The signed
//! bytes are [`name_signature_message`]: SHA-256 over a lab domain, one
//! `0x00` byte and that printed name. [`verify_checked_signature`] checks a
//! signature against a [`CheckedBundle`], in order: a canonical `did:key`,
//! an explicit accepted list, [`CheckedBundle::check_name`], then the
//! Ed25519 signature. [`verify_name_signature`] is [`checked_bundle`] and
//! then that check, so it holds no check of its own. A refusal is one of
//! those checks and nothing else. `Ok(())` means the test key signed that
//! name; it is not a permission to run.
//!
//! # Lab package record
//!
//! A [`PackageRecord`] is the signed record that sits outside the bundle: it
//! names the signer and binds the printed lab CID. Its bytes are
//! [`PackageRecord::package_record_payload`], compact JSON with the keys
//! `cid`, `schema` ([`PACKAGE_RECORD_SCHEMA`]) and `signer_did`, and no name
//! field. [`sign_package_record`] signs [`domain_separated_digest`] of
//! [`PACKAGE_RECORD_DOMAIN`] and that payload; it writes nothing.
//! [`verify_checked_package_record`] checks, in order, the signer's
//! `did:key`, the explicit accepted list, the record's CID against the
//! checked bundle's, then the Ed25519 signature. [`verify_package_record`]
//! is [`checked_bundle`] and then that check. Both signatures share one
//! digest, one DID encoder and decoder, one accepted-list check and one
//! Ed25519 verification. `Ok(())` grants nothing.
//!
//! # Lab variant binding
//!
//! A [`VariantBinding`] sits outside every bundle and groups the printed lab
//! CIDs of a capsule's platform variants, each under a platform label from
//! [`VARIANT_PLATFORMS`], with the lab CID of their recipe. No manifest
//! field, folder name or path holds a platform label, so the binding is the
//! label's only home as metadata. The stand-in payloads of the variant
//! fixtures hold the words only so their CIDs differ; the lab never reads
//! them. A label, the portable `*` too, is the signer's claim: the lab never
//! reads one from a manifest, path or payload, so it does not check that a
//! variant's bytes were built for its label. Its bytes are
//! [`VariantBinding::variant_binding_payload`], compact JSON with the keys
//! `recipe`, `schema` ([`VARIANT_BINDING_SCHEMA`]), `signer_did` and
//! `variants`, and no name or group identity field. [`sign_variant_binding`]
//! signs [`domain_separated_digest`] of [`VARIANT_BINDING_DOMAIN`] and that
//! payload; it writes nothing. [`verify_checked_variant_binding`] checks, in
//! order, the signer's `did:key`, the explicit accepted list, the shape of
//! both variant lists, the platforms, each variant's CID, that a WASM app is
//! bound only under the portable label [`PORTABLE_PLATFORM`] (`*`), the
//! recipe's CID, then the Ed25519 signature. The portable label stands alone
//! in a binding, so a WASM app has one variant and one CID. Whether a bundle
//! is a WASM app comes from the one manifest check, never a second parse.
//! [`verify_variant_binding`] is [`checked_bundle`]
//! for each variant and then that check. It shares the record's digest, DID
//! encoder and decoder, accepted-list check and Ed25519 verification. Each
//! variant is still its own closure with its own [`PackageRecord`]. The
//! binding groups CIDs; it defines no shared capsule identity, and `Ok(())`
//! grants nothing.
//!
//! # The walk reads only checked handles
//!
//! The walk opens the bundle root once, by its path. After that it reaches
//! every entry through its folder's open handle, never by a path:
//!
//! 1. It reads a folder's whole listing from the folder's handle, skipping
//!    `.` and `..`.
//! 2. It refuses a link, FIFO, socket or device from the listing's own type,
//!    without opening it.
//! 3. It opens each other entry relative to its folder's handle, never
//!    following a link and never waiting on a FIFO.
//! 4. It checks the open handle's own type: a regular file or a folder, and
//!    the kind the listing said.
//! 5. It reads a file's bytes from that same handle, and lists a folder from
//!    it.
//!
//! So an entry changed while the bundle is named is refused, or named
//! exactly as the bytes its checked handle held.
#![forbid(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use elastos_common::{CapsuleManifest, CapsuleType};
use rustix::fs::{fstat, openat, Dir, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

/// The first bytes of every lab CID stream.
pub const FRAMING_TAG: &[u8] = b"lab.capsule-identity.bundle/v1\n";

/// How a lab CID prints before its 64 lowercase hex characters.
pub const LAB_CID_PREFIX: &str = "lab-cid:sha256:";

/// The manifest every bundle holds at its root.
pub const MANIFEST_FILE: &str = "capsule.json";

/// Domain of the lab name signature, for [`domain_separated_digest`]. It is a
/// lab proposal.
pub const NAME_SIGNATURE_DOMAIN: &str = "lab.capsule-identity.name-signature/v1";

/// Schema of the lab package record's payload. It is the lab's own name, not
/// the Runtime's capsule record schema.
pub const PACKAGE_RECORD_SCHEMA: &str = "lab.capsule-identity.record/v1";

/// Domain of the lab package record's signature, for
/// [`domain_separated_digest`]. It is a lab proposal.
pub const PACKAGE_RECORD_DOMAIN: &str = "lab.capsule-identity.package-record/v1";

/// Schema of the lab variant binding's payload. It is the lab's own name.
pub const VARIANT_BINDING_SCHEMA: &str = "lab.capsule-identity.variant-binding/v1";

/// Domain of the lab variant binding's signature, for
/// [`domain_separated_digest`]. It is a lab proposal.
pub const VARIANT_BINDING_DOMAIN: &str = "lab.capsule-identity.variant-binding/v1";

/// The portable label: one variant that is not per platform, as the Runtime's
/// own record writes `"platform": "*"`. A binding that holds it holds no other
/// label, and a bundle whose manifest `type` is `wasm` is bound only under it.
pub const PORTABLE_PLATFORM: &str = "*";

/// The labels a variant binding may hold, in byte order: the portable label
/// and the three platforms the Runtime's release script uses. A label is not
/// identity. No manifest field, folder name or path holds one, so as metadata
/// it lives only in the binding. A stand-in payload may hold a label's words
/// (the variant fixtures' do, only so their CIDs differ), but the lab never
/// reads them: a label is the signer's claim.
pub const VARIANT_PLATFORMS: [&str; 4] = [
    PORTABLE_PLATFORM,
    "aarch64-darwin",
    "aarch64-linux",
    "x86_64-linux",
];

/// The path of the one entry a variant recipe is named under: its lab CID is
/// [`encode_entries`] of one entry with this path and the recipe's bytes.
pub const VARIANT_RECIPE_ENTRY: &str = "provider-variant.recipe";

/// A lab CID: SHA-256 over a bundle's lab CID stream. It prints with its
/// `lab-cid:sha256:` label so it is never mistaken for the Runtime's CID.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabCid([u8; 32]);

impl fmt::Display for LabCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{LAB_CID_PREFIX}{}", hex::encode(self.0))
    }
}

impl fmt::Debug for LabCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabCid({self})")
    }
}

/// Read a printed lab CID back into its value.
///
/// It runs the claim check both name checks run, `lab_cid_digits`, and
/// then decodes the digits it gives, so a printed value is read in one
/// place and a consumer never copies the printed form. Text that is not a
/// lab CID is refused with [`Refusal::NotALabCid`], the same refusal and
/// text a name check gives. Parsing is not a name check: the value names no
/// bytes until [`check_name`] or [`CheckedBundle::check_name`] compares it.
impl std::str::FromStr for LabCid {
    type Err = Refusal;

    fn from_str(printed: &str) -> Result<Self, Refusal> {
        let digits = lab_cid_digits(printed)?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(digits, &mut bytes).map_err(|_| Refusal::NotALabCid {
            claimed: printed.to_owned(),
        })?;
        Ok(LabCid(bytes))
    }
}

/// One regular file of a bundle: its bundle-relative, `/`-separated path and
/// its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub content: Vec<u8>,
}

/// A bundle as the one walk checked it: its lab CID and every regular file
/// the walk read, each with the bytes read from its checked handle.
///
/// Only [`checked_bundle`] and [`checked_bundle_observed`] make one, from the
/// one walk and the one manifest check. Its fields are private and nothing
/// changes them, so its lab CID always names its entries. It also keeps
/// whether that manifest check found `type` to be `wasm`, for the variant
/// binding's check (e2) alone; no accessor hands it out. It holds a name and
/// bytes, never a decision: it is no trust, admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBundle {
    cid: LabCid,
    entries: Vec<BundleEntry>,
    wasm: bool,
}

/// A test-key signature over a printed lab CID.
///
/// It lives in memory only. It is not a file, an envelope or a manifest
/// field, and nothing writes it to disk. It has no serialized form. The
/// signature never goes into `capsule.json`: that file is inside the bytes
/// the lab CID covers, so a signature written there would change the name it
/// signs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameSignature {
    /// The printed lab CID the signature covers, label included.
    pub name: String,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`name_signature_message`] of
    /// [`NameSignature::name`].
    pub signature: [u8; 64],
}

/// A test-key signed record, outside the bundle, that names the signer and
/// binds a printed lab CID.
///
/// It lives in memory only, like [`NameSignature`]: no serde derive, no file,
/// and nothing writes it into or next to the bundle. It has no name field, so
/// it binds a CID and never a capsule name. The signature is not part of the
/// payload it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageRecord {
    /// The printed lab CID the record binds, as `LabCid`'s `Display` prints it.
    pub cid: String,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`domain_separated_digest`] of
    /// [`PACKAGE_RECORD_DOMAIN`] and [`PackageRecord::package_record_payload`].
    pub signature: [u8; 64],
}

/// A test-key signed binding, outside every bundle, that groups the lab CIDs
/// of a capsule's platform variants and the lab CID of their recipe.
///
/// It lives in memory only, like [`PackageRecord`]: no serde derive, no file,
/// and nothing writes it. It has no name and no group identity field: it
/// groups CIDs and defines no shared capsule identity. Each variant is still
/// its own closure with its own [`PackageRecord`]. The signature is not part
/// of the payload it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantBinding {
    /// The recipe's printed lab CID.
    pub recipe: String,
    /// The `(platform, cid)` pairs: a platform label and the printed lab CID
    /// of that variant's bundle, in the order signing was given them. The
    /// payload sorts them.
    pub variants: Vec<(String, String)>,
    /// The signer's canonical Ed25519 `did:key`.
    pub signer_did: String,
    /// The 64-byte Ed25519 signature over [`domain_separated_digest`] of
    /// [`VARIANT_BINDING_DOMAIN`] and [`VariantBinding::variant_binding_payload`].
    pub signature: [u8; 64],
}

/// What the walk does with one entry, decided from the entry's own type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Walked into. A directory adds nothing to the stream itself.
    Directory,
    /// Read and named.
    RegularFile,
    /// Refused: a symlink, FIFO, socket, device or other special file.
    Special(&'static str),
}

/// When the walk tells its observer about one entry under the root. The
/// observer gets the moment and the entry's bundle path and returns nothing,
/// so it cannot steer the walk. Tests use it to change the bundle on disk at
/// that moment, as another process could.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// The entry's name and listed kind are known; nothing is open yet.
    BeforeOpen,
    /// The entry's handle is open and its kind is checked; nothing has been
    /// read or listed from it yet.
    AfterCheck,
}

/// Why a bundle gets no lab CID, why a name check ([`check_name`] or
/// [`CheckedBundle::check_name`]) refuses a claimed name, why a printed lab
/// CID does not parse ([`LabCid`]'s `FromStr`), or why a test-key
/// signature or package record check refuses. Each refusal has its own
/// reason. A refused bundle gets no name, no signature and no record. A
/// refused check returns no trust, admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The bundle root holds no regular file `capsule.json`.
    NoManifest,
    /// The Runtime's `CapsuleManifest` refused to parse `capsule.json`; this
    /// is its error text, which names an unknown field.
    ManifestUnparsed(String),
    /// The Runtime's `CapsuleManifest::validate()` refused `capsule.json`;
    /// this is its error text.
    ManifestInvalid(String),
    /// An entry under the bundle root is neither a regular file nor a
    /// directory.
    NotRegularFile { path: String, kind: &'static str },
    /// An entry's name is not UTF-8. The path shows the name lossily.
    NonUtf8Name { path: String },
    /// Two entries given to the encoder have the same path.
    DuplicatePath { path: String },
    /// An entry's open handle is not the kind its folder's listing said: the
    /// entry changed between the listing and the open.
    Changed { path: String },
    /// The walk could not read an entry; `.` is the bundle root. `reason` is
    /// the system's own text. (The field is not named `error`: falsify.py
    /// takes that word with a colon in test output for a harness error, so a
    /// failing assertion that printed this refusal would never count.)
    Unreadable { path: String, reason: String },
    /// A name check, or [`LabCid`]'s parse, was given a claim that is not a
    /// lab CID: it lacks the `lab-cid:sha256:` label, or 64 lowercase hex
    /// characters after it. The claim is kept only to say what was refused.
    NotALabCid { claimed: String },
    /// A name check was given a lab CID the bundle's bytes do not give.
    /// `actual` is the lab CID of the bytes; the claim is kept only to say
    /// what was refused.
    NameMismatch { actual: LabCid, claimed: String },
    /// The signer DID is not one canonical Ed25519 `did:key`. `reason` is the
    /// decoder's own text.
    MalformedSignerDid { did: String, reason: String },
    /// The signer DID is not an exact member of the explicit accepted list.
    SignerNotAccepted { did: String },
    /// The Ed25519 signature does not verify over the signed name. A wrong
    /// key, a changed signature and a name moved onto other bytes all meet
    /// this one check.
    SignatureDoesNotVerify { did: String, name: String },
    /// A package record binds a CID that is not the checked bundle's. `record`
    /// is the record's CID, kept only to say what was refused; `bundle` is the
    /// lab CID of the checked bytes.
    RecordNamesAnotherCid { record: String, bundle: LabCid },
    /// A variant list holds no variant. `list` says whose: `binding` (the
    /// binding's pairs) or `given` (the pairs given to sign or verify).
    NoVariants { list: &'static str },
    /// A variant list holds a label that is not one of [`VARIANT_PLATFORMS`].
    UnknownPlatform { list: &'static str, label: String },
    /// A variant list holds one label twice.
    DuplicatePlatform { list: &'static str, label: String },
    /// The platforms given are not the binding's platforms. Both lists are
    /// sorted in byte order.
    PlatformsDiffer {
        binding: Vec<String>,
        given: Vec<String>,
    },
    /// A binding names, for `platform`, a CID that is not the given bundle's.
    /// `binding` is the binding's CID, kept only to say what was refused;
    /// `bundle` is the lab CID of the checked bytes given for that platform.
    VariantNamesAnotherCid {
        platform: String,
        binding: String,
        bundle: LabCid,
    },
    /// A binding names a recipe CID that is not the lab CID of the recipe
    /// bytes given. `binding` is the binding's CID; `recipe` is the bytes'.
    RecipeNamesAnotherCid { binding: String, recipe: LabCid },
    /// A variant list holds the portable label [`PORTABLE_PLATFORM`] and
    /// another label. `labels` is the whole list, sorted in byte order.
    PortableNotAlone {
        list: &'static str,
        labels: Vec<String>,
    },
    /// A bundle whose manifest `type` is `wasm` is bound under `platform`, a
    /// label that is not [`PORTABLE_PLATFORM`]. `bundle` is its lab CID.
    WasmNotPortable { platform: String, bundle: LabCid },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoManifest => write!(f, "no {MANIFEST_FILE} file at the bundle root"),
            Refusal::ManifestUnparsed(error) => write!(
                f,
                "the Runtime's CapsuleManifest refused to parse {MANIFEST_FILE}: {error}"
            ),
            Refusal::ManifestInvalid(error) => write!(
                f,
                "the Runtime's CapsuleManifest::validate() refused {MANIFEST_FILE}: {error}"
            ),
            Refusal::NotRegularFile { path, kind } => write!(
                f,
                "{path} is a {kind}: the lab CID covers only regular files and never follows a link"
            ),
            Refusal::NonUtf8Name { path } => write!(
                f,
                "{path} has a name that is not UTF-8: the lab CID names only UTF-8 paths"
            ),
            Refusal::DuplicatePath { path } => write!(
                f,
                "two entries have the path {path}: a bundle holds one file per path"
            ),
            Refusal::Changed { path } => write!(f, "{path} changed while the bundle was named"),
            Refusal::Unreadable { path, reason } => write!(f, "could not read {path}: {reason}"),
            Refusal::NotALabCid { claimed } => write!(
                f,
                "the claim {claimed:?} is not a lab CID: a lab CID is {LAB_CID_PREFIX} and 64 lowercase hex characters"
            ),
            Refusal::NameMismatch { actual, claimed } => {
                write!(f, "bundle bytes name {actual}; the claim is {claimed}")
            }
            Refusal::MalformedSignerDid { did, reason } => write!(
                f,
                "signer DID {did} is not a canonical Ed25519 did:key: {reason}"
            ),
            Refusal::SignerNotAccepted { did } => {
                write!(f, "signer {did} is not in the accepted list")
            }
            Refusal::SignatureDoesNotVerify { did, name } => {
                write!(f, "signature by {did} does not verify over {name}")
            }
            Refusal::RecordNamesAnotherCid { record, bundle } => {
                write!(f, "record names {record}; the bundle names {bundle}")
            }
            Refusal::NoVariants { list } => write!(
                f,
                "the {list} variant list is empty: a binding holds at least one variant"
            ),
            Refusal::UnknownPlatform { list, label } => write!(
                f,
                "the {list} variant list holds the platform {label:?}, which is not one of {}",
                VARIANT_PLATFORMS.join(", ")
            ),
            Refusal::DuplicatePlatform { list, label } => write!(
                f,
                "the {list} variant list holds the platform {label} twice: one CID per platform"
            ),
            Refusal::PlatformsDiffer { binding, given } => write!(
                f,
                "the binding holds the platforms {binding:?}; the given variants are {given:?}"
            ),
            Refusal::VariantNamesAnotherCid {
                platform,
                binding,
                bundle,
            } => write!(
                f,
                "the binding names {binding} for {platform}; the bundle given for {platform} names {bundle}"
            ),
            Refusal::RecipeNamesAnotherCid { binding, recipe } => write!(
                f,
                "the binding names the recipe {binding}; the recipe bytes name {recipe}"
            ),
            Refusal::PortableNotAlone { list, labels } => write!(
                f,
                "the {list} variant list holds the labels {labels:?}: the portable label {PORTABLE_PLATFORM} stands alone"
            ),
            Refusal::WasmNotPortable { platform, bundle } => write!(
                f,
                "the bundle {bundle} is a WASM app bound under {platform}: a WASM app has one portable variant, bound under {PORTABLE_PLATFORM}"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Name the bundle at `bundle` by its lab CID.
///
/// This is [`lab_cid_observed`] with an observer that does nothing: the same
/// walk, not a second one. A refusal returns no name.
pub fn lab_cid(bundle: &Path) -> Result<LabCid, Refusal> {
    lab_cid_observed(bundle, |_, _| {})
}

/// Name the bundle at `bundle` by its lab CID, telling `observe` about each
/// entry under the root at two [`Moment`]s.
///
/// This is [`checked_bundle_observed`]'s lab CID: the same walk and the same
/// manifest check, not a second one. A refusal returns no name.
pub fn lab_cid_observed(
    bundle: &Path,
    observe: impl FnMut(Moment, &str),
) -> Result<LabCid, Refusal> {
    Ok(checked_bundle_observed(bundle, observe)?.cid())
}

/// Check the bundle at `bundle` and keep what was checked: its lab CID and
/// the bytes that lab CID names.
///
/// This is [`checked_bundle_observed`] with an observer that does nothing:
/// the same walk, not a second one. A refusal returns no value.
pub fn checked_bundle(bundle: &Path) -> Result<CheckedBundle, Refusal> {
    checked_bundle_observed(bundle, |_, _| {})
}

/// Check the bundle at `bundle` and keep what was checked, telling `observe`
/// about each entry under the root at two [`Moment`]s.
///
/// The walk checks each entry's listed type before it opens it and its open
/// handle's type before it reads or lists it; it never follows a link and
/// never waits on a FIFO. It reads every regular file once, from its checked
/// handle. Then the root `capsule.json` it read gets the Runtime's own two
/// checks, and exactly the bytes that were checked are named and kept, with
/// whether that check found `type` to be `wasm`. This is the one walk and the
/// one manifest check. A refusal returns no value.
pub fn checked_bundle_observed(
    bundle: &Path,
    mut observe: impl FnMut(Moment, &str),
) -> Result<CheckedBundle, Refusal> {
    let entries = collect_entries(bundle, &mut observe)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or(Refusal::NoManifest)?;
    let wasm = check_manifest(&manifest.content)?;
    encode_entries(&entries)
        // The value keeps the very entries its lab CID names: no second read.
        .map(|cid| CheckedBundle { cid, entries, wasm })
}

/// Check the name `claimed` against the bundle at `bundle`.
///
/// A name that a URL, a Store row or any other record claims is checked
/// here, never trusted. A claim that is not a lab CID is refused before the
/// bundle is read. Then the name is recomputed from the bytes with
/// [`lab_cid`], the one naming path, and compared: a lab CID the bytes do not
/// give is refused with both values, and `lab_cid`'s own refusals pass
/// through unchanged. Success returns nothing, so a claim never comes back
/// as a checked name. [`CheckedBundle::check_name`] is the checked form.
pub fn check_name(bundle: &Path, claimed: &str) -> Result<(), Refusal> {
    let claimed_digits = lab_cid_digits(claimed)?;
    let actual = lab_cid(bundle)?;
    compare_name(actual, claimed_digits, claimed)
}

impl CheckedBundle {
    /// The lab CID of [`CheckedBundle::entries`].
    pub fn cid(&self) -> LabCid {
        self.cid
    }

    /// Every regular file the walk read: its bundle path and the bytes read
    /// from its checked handle. They come in the walk's order; the encoder
    /// sorts them, and a caller that needs an order sorts them by path.
    pub fn entries(&self) -> &[BundleEntry] {
        &self.entries
    }

    /// Check the name `claimed` against this bundle's lab CID.
    ///
    /// The checked form of [`check_name`]: the same claim check, then the
    /// same compare, with the same refusals. It reads nothing, so it judges
    /// exactly the bytes in [`CheckedBundle::entries`], even when the folder
    /// has changed since. Success returns nothing.
    pub fn check_name(&self, claimed: &str) -> Result<(), Refusal> {
        let claimed_digits = lab_cid_digits(claimed)?;
        compare_name(self.cid, claimed_digits, claimed)
    }
}

/// The compare both name checks make: a lab CID whose digits are not the
/// claim's digits is refused with both values. `claimed` is the whole
/// claim, kept only to say what was refused.
fn compare_name(actual: LabCid, claimed_digits: &str, claimed: &str) -> Result<(), Refusal> {
    if hex::encode(actual.0) != claimed_digits {
        return Err(Refusal::NameMismatch {
            actual,
            claimed: claimed.to_owned(),
        });
    }
    Ok(())
}

/// The digits of a claimed lab CID: the 64 lowercase hex characters after
/// its `lab-cid:sha256:` label. Any other text is not a lab CID.
fn lab_cid_digits(claimed: &str) -> Result<&str, Refusal> {
    let not_a_lab_cid = || Refusal::NotALabCid {
        claimed: claimed.to_owned(),
    };
    let digits = claimed
        .strip_prefix(LAB_CID_PREFIX)
        .ok_or_else(not_a_lab_cid)?;
    if digits.len() != 64 {
        return Err(not_a_lab_cid());
    }
    if !digits
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(not_a_lab_cid());
    }
    Ok(digits)
}

/// The encoder: the lab CID of `entries`, given in any order.
///
/// It sorts the entries by path bytes, refuses two entries with one path, and
/// hashes [`FRAMING_TAG`] and then, for each entry, the path length (u64
/// big-endian), the path, the content length (u64 big-endian) and the
/// content. The two length prefixes keep every path and content boundary
/// unambiguous.
pub fn encode_entries(entries: &[BundleEntry]) -> Result<LabCid, Refusal> {
    let mut sorted: Vec<&BundleEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    if let Some(pair) = sorted.windows(2).find(|pair| pair[0].path == pair[1].path) {
        return Err(Refusal::DuplicatePath {
            path: pair[0].path.clone(),
        });
    }
    let mut hasher = Sha256::new();
    hasher.update(FRAMING_TAG);
    for entry in sorted {
        hasher.update((entry.path.len() as u64).to_be_bytes());
        hasher.update(entry.path.as_bytes());
        hasher.update((entry.content.len() as u64).to_be_bytes());
        hasher.update(&entry.content);
    }
    Ok(LabCid(hasher.finalize().into()))
}

/// The kind of one entry, from its own type: as its folder's listing reports
/// it, or as `fstat` reports its open handle. Only a directory or a regular
/// file may be in a bundle; everything else is [`EntryKind::Special`].
pub fn entry_kind(file_type: FileType) -> EntryKind {
    if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::RegularFile
    } else {
        EntryKind::Special(special_name(file_type))
    }
}

/// The bundle-relative path of the entry `name` in the folder `parent`
/// (empty for the bundle root). A name that is not UTF-8 is refused, never
/// converted lossily.
pub fn entry_path(parent: &str, name: &OsStr) -> Result<String, Refusal> {
    let join = |name: &str| {
        if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        }
    };
    match name.to_str() {
        Some(name) => Ok(join(name)),
        None => Err(Refusal::NonUtf8Name {
            path: join(&name.to_string_lossy()),
        }),
    }
}

/// One entry of a folder's listing: its name in the folder, its bundle
/// path, and the type the listing gave it.
struct Listed {
    name: CString,
    path: String,
    file_type: FileType,
}

/// A folder the walk is in: its checked handle and the rest of its listing.
struct Folder {
    handle: OwnedFd,
    listing: std::vec::IntoIter<Listed>,
}

/// Every regular file under `bundle`, each with its bundle-relative path.
///
/// The walk opens `bundle` once, as a folder. After that it reaches each
/// entry through its folder's handle: it checks the listed type, opens the
/// entry, checks the open handle, and only then reads or lists that handle.
/// It goes depth first, so it holds one handle per folder level. The first
/// refusal stops the walk. Listing order does not matter: the encoder sorts.
fn collect_entries(
    bundle: &Path,
    observe: &mut dyn FnMut(Moment, &str),
) -> Result<Vec<BundleEntry>, Refusal> {
    let root = open_checked(CWD, bundle, EntryKind::Directory, "")?;
    let listing = list_folder(root.as_fd(), "")?;
    let mut folders = vec![Folder {
        handle: root,
        listing,
    }];
    let mut entries = Vec::new();
    while let Some(folder) = folders.last_mut() {
        let Some(Listed {
            name,
            path,
            file_type,
        }) = folder.listing.next()
        else {
            folders.pop();
            continue;
        };
        let kind = match entry_kind(file_type) {
            EntryKind::Special(kind) => return Err(Refusal::NotRegularFile { path, kind }),
            kind => kind,
        };
        observe(Moment::BeforeOpen, &path);
        let handle = open_checked(folder.handle.as_fd(), name.as_c_str(), kind, &path)?;
        observe(Moment::AfterCheck, &path);
        if kind == EntryKind::Directory {
            let listing = list_folder(handle.as_fd(), &path)?;
            folders.push(Folder { handle, listing });
        } else {
            let content = read_file(handle, &path)?;
            entries.push(BundleEntry { path, content });
        }
    }
    Ok(entries)
}

/// The whole listing of the folder open at `folder`, read from that handle
/// before any entry in it is opened. `prefix` is the folder's bundle path.
/// `.` and `..` are the folder itself and its parent, so they are skipped.
fn list_folder(
    folder: BorrowedFd<'_>,
    prefix: &str,
) -> Result<std::vec::IntoIter<Listed>, Refusal> {
    let mut listing = Vec::new();
    for item in Dir::read_from(folder).map_err(|error| unreadable(prefix, error))? {
        let item = item.map_err(|error| unreadable(prefix, error))?;
        let name = item.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        listing.push(Listed {
            path: entry_path(prefix, OsStr::from_bytes(name.to_bytes()))?,
            name: name.to_owned(),
            file_type: item.file_type(),
        });
    }
    Ok(listing.into_iter())
}

/// The flags of every open: read only, never follow a link, never wait on a
/// FIFO, and close on exec. A folder is opened as a folder, so the open
/// fails unless it is one.
fn open_flags(kind: EntryKind) -> OFlags {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if kind == EntryKind::Directory {
        flags | OFlags::DIRECTORY
    } else {
        flags
    }
}

/// Open `name` relative to the folder handle `folder`, then check the open
/// handle's own type: it must be a regular file or a folder, and the kind the
/// listing said. The bundle root is the one entry opened by a path: its
/// `folder` is the working folder (`CWD`) and its `name` is the root's
/// path. `path` is the entry's bundle path, for a refusal.
fn open_checked(
    folder: BorrowedFd<'_>,
    name: impl rustix::path::Arg,
    listed: EntryKind,
    path: &str,
) -> Result<OwnedFd, Refusal> {
    let handle = openat(folder, name, open_flags(listed), Mode::empty())
        .map_err(|error| open_refusal(path, listed, error))?;
    let stat = fstat(&handle).map_err(|error| unreadable(path, error))?;
    match entry_kind(FileType::from_raw_mode(stat.st_mode)) {
        EntryKind::Special(kind) => Err(Refusal::NotRegularFile {
            path: shown(path),
            kind,
        }),
        opened if opened != listed => Err(Refusal::Changed { path: shown(path) }),
        _ => Ok(handle),
    }
}

/// Why an open failed. A file's name is one path part opened with the
/// no-follow flag, so `ELOOP` means it is now a link: it gets the link's own
/// refusal. Every other failure keeps the system's own reason. (A folder is
/// opened as a folder: on macOS a link there fails with "Not a directory".)
fn open_refusal(path: &str, listed: EntryKind, errno: Errno) -> Refusal {
    if errno == Errno::LOOP && listed == EntryKind::RegularFile {
        Refusal::NotRegularFile {
            path: shown(path),
            kind: special_name(FileType::Symlink),
        }
    } else {
        unreadable(path, errno)
    }
}

/// The bytes of the regular file open at `handle`, read from that handle.
fn read_file(handle: OwnedFd, path: &str) -> Result<Vec<u8>, Refusal> {
    let mut content = Vec::new();
    File::from(handle)
        .read_to_end(&mut content)
        .map_err(|error| unreadable(path, error))?;
    Ok(content)
}

/// The Runtime's own two checks on `capsule.json`, the same two calls it
/// makes on a fetched bundle's manifest: parse it as `CapsuleManifest`
/// (which refuses an unknown field), then `validate()`. The lab adds no rule.
/// It returns whether the parsed manifest's `type` is `wasm`, read from that
/// one parse: nothing else parses `capsule.json`.
fn check_manifest(bytes: &[u8]) -> Result<bool, Refusal> {
    let manifest: CapsuleManifest = serde_json::from_slice(bytes)
        .map_err(|error| Refusal::ManifestUnparsed(error.to_string()))?;
    let wasm = manifest.capsule_type == CapsuleType::Wasm;
    manifest.validate().map_err(Refusal::ManifestInvalid)?;
    Ok(wasm)
}

fn special_name(file_type: FileType) -> &'static str {
    if file_type.is_symlink() {
        "symbolic link"
    } else if file_type.is_fifo() {
        "FIFO"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_block_device() {
        "block device"
    } else if file_type.is_char_device() {
        "character device"
    } else {
        "special file"
    }
}

/// A bundle path as a refusal shows it: `.` is the bundle root.
fn shown(path: &str) -> String {
    if path.is_empty() {
        ".".to_owned()
    } else {
        path.to_owned()
    }
}

/// The refusal for an entry the walk could not open, check, list or read,
/// with the system's own reason.
fn unreadable(path: &str, reason: impl Into<io::Error>) -> Refusal {
    Refusal::Unreadable {
        path: shown(path),
        reason: reason.into().to_string(),
    }
}

/// The digest every lab signature covers: SHA-256 over the UTF-8 bytes of
/// `domain`, one `0x00` byte and `payload`.
///
/// This is the three-step form of `domain_separated_sign` in
/// `elastos/crates/elastos-server/src/crypto.rs`. That form lives only in the
/// Runtime server, which this lab does not link, so the lab keeps this one
/// marked copy and calls it a lab proposal. It is the one message hash: the
/// name signature and the package record both call it, each with its own
/// domain. [`encode_entries`] remains the one naming hash.
pub fn domain_separated_digest(domain: &str, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(b"\0");
    hasher.update(payload);
    hasher.finalize().into()
}

/// The bytes a name signature covers: [`domain_separated_digest`] of
/// [`NAME_SIGNATURE_DOMAIN`] and the UTF-8 bytes of the printed lab CID.
///
/// Signing and verifying both call this, and nothing else builds the message.
/// The lab CID's label is part of the signed name.
pub fn name_signature_message(name: &str) -> [u8; 32] {
    domain_separated_digest(NAME_SIGNATURE_DOMAIN, name.as_bytes())
}

/// Sign `bundle`'s printed lab CID with `key`.
///
/// The name comes from [`lab_cid`]. A bundle [`lab_cid`] refuses gets no
/// signature, and the refusal is [`lab_cid`]'s own. The signature is Ed25519
/// over [`name_signature_message`] of that printed name. `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. Nothing is written.
pub fn sign_bundle(key: &SigningKey, bundle: &Path) -> Result<NameSignature, Refusal> {
    let name = lab_cid(bundle)?.to_string();
    let digest = name_signature_message(&name);
    let signature = key.sign(&digest).to_bytes();
    Ok(NameSignature {
        name,
        signer_did: signer_did_of(key),
        signature,
    })
}

/// The canonical Ed25519 `did:key` of `key`, from
/// `elastos_identity::encode_signing_key_did`: the one DID encoding both
/// signers use.
fn signer_did_of(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

/// Check `sig` against the bytes `checked` holds.
///
/// The checks run in this order, and the first refusal is the answer:
///
/// 1. `elastos_identity::decode_did_key` on `sig.signer_did`. A DID it refuses
///    is not a canonical Ed25519 `did:key`, and the reason carries the
///    decoder's own text.
/// 2. `sig.signer_did` is an exact member of `accepted`. An empty list refuses
///    every signer. The list is an explicit input, not a trust policy.
/// 3. [`CheckedBundle::check_name`] of `sig.name`. Its refusals pass through
///    unchanged. This reads nothing from disk.
/// 4. Ed25519 verification of `sig.signature` over [`name_signature_message`]
///    of `sig.name`, with the key from step 1.
///
/// `Ok(())` means all four passed. It is not a trust, admission or launch
/// value. A wrong key, a changed signature and a name moved onto other bytes
/// all fail step 4 with one reason.
pub fn verify_checked_signature(
    checked: &CheckedBundle,
    sig: &NameSignature,
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&sig.signer_did)?;
    require_accepted(&sig.signer_did, accepted)?;
    checked.check_name(&sig.name)?;
    verify_signature(&key, sig)?;
    Ok(())
}

/// Check `sig` against the bundle at `bundle`.
///
/// This is [`checked_bundle`] and then [`verify_checked_signature`]. It holds
/// no check of its own, so a bundle the walk refuses is refused first, with
/// the walk's own reason. The signature is judged on the bytes that walk read.
pub fn verify_name_signature(
    bundle: &Path,
    sig: &NameSignature,
    accepted: &[String],
) -> Result<(), Refusal> {
    let checked = checked_bundle(bundle)?;
    verify_checked_signature(&checked, sig, accepted)
}

/// Check (a): `did` is one canonical Ed25519 `did:key`.
fn decode_signer(did: &str) -> Result<VerifyingKey, Refusal> {
    elastos_identity::decode_did_key(did).map_err(|error| Refusal::MalformedSignerDid {
        did: did.to_owned(),
        reason: error.to_string(),
    })
}

/// Check (b): `did` is an exact member of `accepted`.
fn require_accepted(did: &str, accepted: &[String]) -> Result<(), Refusal> {
    if !accepted.iter().any(|one| one == did) {
        return Err(Refusal::SignerNotAccepted {
            did: did.to_owned(),
        });
    }
    Ok(())
}

/// Check (d): Ed25519 verification of `sig` over the message of its name.
fn verify_signature(key: &VerifyingKey, sig: &NameSignature) -> Result<(), Refusal> {
    let digest = name_signature_message(&sig.name);
    verify_ed25519(key, &digest, &sig.signature, &sig.signer_did, &sig.name)
}

/// The one Ed25519 verification: `signature` by `key` over `digest`. A
/// failure is refused with the signer `did` and the signed `name`.
fn verify_ed25519(
    key: &VerifyingKey,
    digest: &[u8; 32],
    signature: &[u8; 64],
    did: &str,
    name: &str,
) -> Result<(), Refusal> {
    let signature = Signature::from_bytes(signature);
    key.verify(digest, &signature)
        .map_err(|_| Refusal::SignatureDoesNotVerify {
            did: did.to_owned(),
            name: name.to_owned(),
        })?;
    Ok(())
}

impl PackageRecord {
    /// The bytes the record's signature covers: compact JSON, keys in this
    /// order, no spaces and no trailing newline:
    /// `{"cid":"<cid>","schema":"lab.capsule-identity.record/v1","signer_did":"<did>"}`.
    ///
    /// This is the only builder of those bytes. The signature is not in them,
    /// and there is no name field. The values are written as they are: when
    /// verification hashes these bytes, check (a) has already decoded the DID
    /// as a canonical `did:key` and check (c) has already found the CID equal
    /// to a printed lab CID, so neither holds a character JSON would escape.
    pub fn package_record_payload(&self) -> Vec<u8> {
        format!(
            "{{\"cid\":\"{}\",\"schema\":\"{}\",\"signer_did\":\"{}\"}}",
            self.cid, PACKAGE_RECORD_SCHEMA, self.signer_did
        )
        .into_bytes()
    }
}

/// The digest a package record's signature covers: [`domain_separated_digest`]
/// of [`PACKAGE_RECORD_DOMAIN`] and [`PackageRecord::package_record_payload`].
/// Signing and verifying both call this.
fn package_record_message(record: &PackageRecord) -> [u8; 32] {
    domain_separated_digest(PACKAGE_RECORD_DOMAIN, &record.package_record_payload())
}

/// Sign a package record for `bundle` with `key`.
///
/// The CID is [`lab_cid`]'s printed form; a bundle [`lab_cid`] refuses gets no
/// record, and the refusal is [`lab_cid`]'s own. `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. The signature is
/// Ed25519 over [`domain_separated_digest`] of [`PACKAGE_RECORD_DOMAIN`] and
/// the record's payload. It writes no file and changes no bundle byte.
pub fn sign_package_record(key: &SigningKey, bundle: &Path) -> Result<PackageRecord, Refusal> {
    let cid = lab_cid(bundle)?.to_string();
    let signer_did = signer_did_of(key);
    let mut record = PackageRecord {
        cid,
        signer_did,
        signature: [0; 64],
    };
    record.signature = key.sign(&package_record_message(&record)).to_bytes();
    Ok(record)
}

/// Check `record` against the bytes `checked` holds.
///
/// The checks run in this order, and the first refusal is the answer:
///
/// 1. `elastos_identity::decode_did_key` on `record.signer_did`, with the name
///    signature's reason.
/// 2. `record.signer_did` is an exact member of `accepted`, with the name
///    signature's reason. An empty list refuses every signer.
/// 3. `record.cid` is `checked.cid()`'s printed form. Otherwise it is refused
///    naming both. This reads nothing from disk.
/// 4. Ed25519 verification of `record.signature` over the record's digest,
///    with the key from step 1 and the name signature's reason.
///
/// `Ok(())` means all four passed. It is not a trust, admission or launch
/// value, and it grants nothing.
pub fn verify_checked_package_record(
    checked: &CheckedBundle,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&record.signer_did)?;
    require_accepted(&record.signer_did, accepted)?;
    require_record_cid(checked, record)?;
    let message = package_record_message(record);
    verify_ed25519(
        &key,
        &message,
        &record.signature,
        &record.signer_did,
        &record.cid,
    )?;
    Ok(())
}

/// Check `record` against the bundle at `bundle`.
///
/// This is [`checked_bundle`] and then [`verify_checked_package_record`]. It
/// holds no check of its own, so a bundle the walk refuses is refused first,
/// with the walk's own reason.
pub fn verify_package_record(
    bundle: &Path,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    let held = checked_bundle(bundle)?;
    verify_checked_package_record(&held, record, accepted)
}

/// Check (c) of a package record: it binds the checked bundle's printed CID.
fn require_record_cid(checked: &CheckedBundle, record: &PackageRecord) -> Result<(), Refusal> {
    if record.cid != checked.cid().to_string() {
        return Err(Refusal::RecordNamesAnotherCid {
            record: record.cid.clone(),
            bundle: checked.cid(),
        });
    }
    Ok(())
}

impl VariantBinding {
    /// The bytes the binding's signature covers: compact JSON, keys in this
    /// order, no spaces and no trailing newline, the variants sorted by
    /// platform label in byte order:
    /// `{"recipe":"<cid>","schema":"lab.capsule-identity.variant-binding/v1","signer_did":"<did>","variants":[{"cid":"<cid>","platform":"<label>"},...]}`.
    ///
    /// This is the only builder of those bytes, and the one place the pairs
    /// are sorted, so the order they were given in does not change them. The
    /// signature is not in them, and there is no name or group identity
    /// field. The values are written as they are: when verification hashes
    /// these bytes, check (a) has decoded the DID as a canonical `did:key`,
    /// check (c) has found every label in [`VARIANT_PLATFORMS`], and checks
    /// (e) and (f) have found every CID equal to a printed lab CID, so none
    /// holds a character JSON would escape.
    pub fn variant_binding_payload(&self) -> Vec<u8> {
        let mut pairs: Vec<&(String, String)> = self.variants.iter().collect();
        pairs.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let variants: Vec<String> = pairs
            .iter()
            .map(|(platform, cid)| format!("{{\"cid\":\"{cid}\",\"platform\":\"{platform}\"}}"))
            .collect();
        format!(
            "{{\"recipe\":\"{}\",\"schema\":\"{}\",\"signer_did\":\"{}\",\"variants\":[{}]}}",
            self.recipe,
            VARIANT_BINDING_SCHEMA,
            self.signer_did,
            variants.join(",")
        )
        .into_bytes()
    }
}

/// The digest a variant binding's signature covers: [`domain_separated_digest`]
/// of [`VARIANT_BINDING_DOMAIN`] and `payload`, the binding's
/// [`VariantBinding::variant_binding_payload`]. Signing and verifying both
/// call this.
fn variant_binding_message(payload: &[u8]) -> [u8; 32] {
    domain_separated_digest(VARIANT_BINDING_DOMAIN, payload)
}

/// The lab CID of a variant recipe: [`encode_entries`], the one encoder, of
/// one entry at [`VARIANT_RECIPE_ENTRY`] holding `recipe`. Nothing here reads
/// the recipe from disk; the caller gives its bytes.
fn recipe_cid(recipe: &[u8]) -> Result<LabCid, Refusal> {
    encode_entries(&[BundleEntry {
        path: VARIANT_RECIPE_ENTRY.to_owned(),
        content: recipe.to_vec(),
    }])
}

/// Sign a variant binding with `key` for the bundles in `variants`, each
/// given with its platform label, and the recipe bytes `recipe`.
///
/// It first refuses the shapes verification refuses (check (c), for the
/// `given` list): no variant, a label not in [`VARIANT_PLATFORMS`], one label
/// twice, or [`PORTABLE_PLATFORM`] with another label. Then it checks each
/// bundle with [`checked_bundle`], the one walk, which gives both its lab CID
/// and its manifest type; a bundle the walk refuses gets no binding, and the
/// refusal is the walk's own. Then it refuses what check (e2) refuses, with
/// the same function: a `wasm` bundle under a label but
/// [`PORTABLE_PLATFORM`]. The recipe is named with [`encode_entries`] of one
/// entry. `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. The signature is
/// Ed25519 over [`domain_separated_digest`] of [`VARIANT_BINDING_DOMAIN`] and
/// the binding's payload. It writes no file and changes no bundle byte.
pub fn sign_variant_binding(
    key: &SigningKey,
    variants: &[(&str, &Path)],
    recipe: &[u8],
) -> Result<VariantBinding, Refusal> {
    let labels = variants.iter().map(|(platform, _)| *platform);
    require_variant_shape("given", labels)?;
    let mut walked = Vec::new();
    for (platform, bundle) in variants {
        walked.push((*platform, checked_bundle(bundle)?));
    }
    require_portable_wasm(
        walked
            .iter()
            .map(|(platform, checked)| (*platform, checked)),
    )?;
    let mut binding = VariantBinding {
        variants: walked
            .iter()
            .map(|(platform, checked)| ((*platform).to_owned(), checked.cid().to_string()))
            .collect(),
        recipe: recipe_cid(recipe)?.to_string(),
        signer_did: signer_did_of(key),
        signature: [0; 64],
    };
    let payload = binding.variant_binding_payload();
    binding.signature = key.sign(&variant_binding_message(&payload)).to_bytes();
    Ok(binding)
}

/// Check `binding` against the checked bundles in `variants`, each given with
/// its platform label, and the recipe bytes `recipe`.
///
/// The checks run in this order, and the first refusal is the answer:
///
/// 1. (a) `elastos_identity::decode_did_key` on `binding.signer_did`, with
///    the name signature's reason.
/// 2. (b) `binding.signer_did` is an exact member of `accepted`, with the name
///    signature's reason. An empty list refuses every signer.
/// 3. (c) The shape of the binding's pairs, then of the given pairs: at least
///    one variant, every label one of [`VARIANT_PLATFORMS`], no label twice,
///    and [`PORTABLE_PLATFORM`] with no other label.
/// 4. (d) The given platforms are the binding's platforms; otherwise both
///    sorted lists are named.
/// 5. (e) Each given bundle's printed lab CID is the binding's CID for its
///    label; otherwise the label and both CIDs are named.
/// 6. (e2) A given bundle whose manifest `type` is `wasm` is bound only under
///    [`PORTABLE_PLATFORM`]; otherwise its label and CID are named. So a WASM
///    app has one variant and one CID.
/// 7. (f) The lab CID of `recipe` is the binding's recipe CID; otherwise
///    both are named.
/// 8. (g) Ed25519 verification of `binding.signature` over the binding's
///    digest, with the key from step 1 and the name signature's reason. The
///    signed name in that reason is the payload, as text.
///
/// It reads nothing from disk. `Ok(())` means all eight passed. It is not a
/// trust, admission or launch value, and it grants nothing.
///
/// Each label is the signer's claim. No check reads a label from a manifest,
/// path or payload, so it is not checked against the bundle's bytes: a
/// variant built for one platform verifies under another label if the signer
/// bound it there.
pub fn verify_checked_variant_binding(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
    recipe: &[u8],
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&binding.signer_did)?;
    require_accepted(&binding.signer_did, accepted)?;
    require_variant_shape(
        "binding",
        binding
            .variants
            .iter()
            .map(|(platform, _)| platform.as_str()),
    )?;
    require_variant_shape("given", variants.iter().map(|(platform, _)| *platform))?;
    require_same_platforms(binding, variants)?;
    require_variant_cids(binding, variants)?;
    require_portable_wasm(variants.iter().copied())?;
    require_recipe_cid(binding, recipe)?;
    let payload = binding.variant_binding_payload();
    let message = variant_binding_message(&payload);
    verify_ed25519(
        &key,
        &message,
        &binding.signature,
        &binding.signer_did,
        &String::from_utf8_lossy(&payload),
    )?;
    Ok(())
}

/// Check `binding` against the bundles at the paths in `variants`, each given
/// with its platform label, and the recipe bytes `recipe`.
///
/// This is [`checked_bundle`] for each path, in the order given, and then
/// [`verify_checked_variant_binding`]. It holds no check of its own, so a
/// bundle the walk refuses is refused first, with the walk's own reason.
pub fn verify_variant_binding(
    binding: &VariantBinding,
    variants: &[(&str, &Path)],
    recipe: &[u8],
    accepted: &[String],
) -> Result<(), Refusal> {
    let walked = variants
        .iter()
        .map(|(platform, bundle)| Ok((*platform, checked_bundle(bundle)?)))
        .collect::<Result<Vec<_>, Refusal>>()?;
    let given: Vec<(&str, &CheckedBundle)> = walked
        .iter()
        .map(|(platform, walked)| (*platform, walked))
        .collect();
    verify_checked_variant_binding(binding, &given, recipe, accepted)
}

/// Check (c) on one list of platform labels; `list` says whose, `binding` or
/// `given`. The first label not in [`VARIANT_PLATFORMS`], or the first label
/// seen twice, is refused; then a list that holds [`PORTABLE_PLATFORM`] and
/// another label is refused naming all its labels; a list with no label is
/// refused.
fn require_variant_shape<'a>(
    list: &'static str,
    labels: impl IntoIterator<Item = &'a str>,
) -> Result<(), Refusal> {
    let mut seen: Vec<&str> = Vec::new();
    for label in labels {
        if !VARIANT_PLATFORMS.contains(&label) {
            return Err(Refusal::UnknownPlatform {
                list,
                label: label.to_owned(),
            });
        }
        if seen.contains(&label) {
            return Err(Refusal::DuplicatePlatform {
                list,
                label: label.to_owned(),
            });
        }
        seen.push(label);
    }
    if seen.len() > 1 && seen.contains(&PORTABLE_PLATFORM) {
        let mut labels: Vec<String> = seen.iter().map(|label| (*label).to_owned()).collect();
        labels.sort();
        return Err(Refusal::PortableNotAlone { list, labels });
    }
    if seen.is_empty() {
        return Err(Refusal::NoVariants { list });
    }
    Ok(())
}

/// Check (d): the given platforms, sorted, are the binding's, sorted.
fn require_same_platforms(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
) -> Result<(), Refusal> {
    let mut bound: Vec<String> = binding
        .variants
        .iter()
        .map(|(platform, _)| platform.clone())
        .collect();
    let mut given: Vec<String> = variants
        .iter()
        .map(|(platform, _)| (*platform).to_owned())
        .collect();
    bound.sort();
    given.sort();
    if bound != given {
        return Err(Refusal::PlatformsDiffer {
            binding: bound,
            given,
        });
    }
    Ok(())
}

/// Check (e): each given bundle, taken in label byte order, has the printed
/// lab CID the binding names for its label. Check (d) has matched the
/// platforms, so every label is bound; were one not, its empty CID would
/// match no bundle and be refused here too.
fn require_variant_cids(
    binding: &VariantBinding,
    variants: &[(&str, &CheckedBundle)],
) -> Result<(), Refusal> {
    let mut given: Vec<&(&str, &CheckedBundle)> = variants.iter().collect();
    given.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for (platform, checked) in given {
        let bound = binding
            .variants
            .iter()
            .find(|(label, _)| label == platform)
            .map_or("", |(_, cid)| cid.as_str());
        if bound != checked.cid().to_string() {
            return Err(Refusal::VariantNamesAnotherCid {
                platform: (*platform).to_owned(),
                binding: bound.to_owned(),
                bundle: checked.cid(),
            });
        }
    }
    Ok(())
}

/// Check (e2), which signing runs too: a bundle whose manifest `type` is
/// `wasm`, as the one manifest check found it, is bound only under
/// [`PORTABLE_PLATFORM`]. Of the bundles under another label, the first in
/// label byte order is refused, naming its label and its lab CID.
fn require_portable_wasm<'a>(
    variants: impl IntoIterator<Item = (&'a str, &'a CheckedBundle)>,
) -> Result<(), Refusal> {
    let refused = variants
        .into_iter()
        .filter(|(platform, checked)| checked.wasm && *platform != PORTABLE_PLATFORM)
        .min_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    match refused {
        Some((platform, checked)) => Err(Refusal::WasmNotPortable {
            platform: platform.to_owned(),
            bundle: checked.cid(),
        }),
        None => Ok(()),
    }
}

/// Check (f): the recipe bytes' lab CID is the binding's recipe CID.
fn require_recipe_cid(binding: &VariantBinding, recipe: &[u8]) -> Result<(), Refusal> {
    let named = recipe_cid(recipe)?;
    if binding.recipe != named.to_string() {
        return Err(Refusal::RecipeNamesAnotherCid {
            binding: binding.recipe.clone(),
            recipe: named,
        });
    }
    Ok(())
}
