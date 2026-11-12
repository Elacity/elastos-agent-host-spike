//! The bundle identity: a capsule bundle's CID, worked out from its files.
//!
//! Moved text for text from `lab/capsule-identity` (M2 part B, slice E1), so that production code
//! can call the one implementation. It names a bundle or refuses; it admits and launches nothing.
#![forbid(unsafe_code)]

use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use elastos_common::{CapsuleManifest, CapsuleType};
use rustix::fs::{fstat, openat, Dir, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
use sha2::{Digest, Sha256};

/// The manifest every bundle holds at its root.
pub const MANIFEST_FILE: &str = "capsule.json";

/// The portable label: one variant that is not per platform, as the Runtime's
/// own record writes `"platform": "*"`. A binding that holds it holds no other
/// label, and a bundle whose manifest `type` is `wasm` is bound only under it.
#[cfg(feature = "lab")]
pub const PORTABLE_PLATFORM: &str = "*";

/// The labels a variant binding may hold, in byte order: the portable label
/// and the three platforms the Runtime's release script uses. A label is not
/// identity. No manifest field, folder name or path holds one, so as metadata
/// it lives only in the binding. A stand-in payload may hold a label's words
/// (the variant fixtures' do, only so their CIDs differ), but the lab never
/// reads them: a label is the signer's claim.
#[cfg(feature = "lab")]
pub const VARIANT_PLATFORMS: [&str; 4] = [
    PORTABLE_PLATFORM,
    "aarch64-darwin",
    "aarch64-linux",
    "x86_64-linux",
];

// The profile: Kubo v0.40.1's import flags as
// `capsules/ipfs-provider/src/directory_hash.rs` `ADD_OPTIONS` sends them, for
// files of up to one tree level and no HAMT shard, computed by the lab (no
// Kubo runs here). Each
// one changes the CID or the refusal, and each has a falsifier. There is no
// inline setting: no CID here uses the identity multihash, whatever the size of the block.

/// CID version 1.
const CID_VERSION: u8 = 0x01;
/// The multihash code of sha2-256 (`hash: sha2-256`).
const SHA2_256: u8 = 0x12;
/// The length of a sha2-256 digest, as its multihash writes it.
const SHA2_256_LENGTH: u8 = 0x20;
/// The codec of a raw leaf (`raw-leaves: true`).
const RAW_CODEC: u8 = 0x55;
/// The codec of a directory block, dag-pb.
const DAG_PB_CODEC: u8 = 0x70;
/// The largest file one raw leaf holds (`chunker: size-262144`). A larger
/// file is split into leaves of this size under one file root.
const CHUNK_SIZE: usize = 262_144;
/// The most leaves one file root links (`max-file-links: 174`). A file of
/// more leaves would need a second tree level, which the lab refuses.
const MAX_FILE_LINKS: usize = 174;
/// The UnixFS data type of a directory, written in its block as `08 01`.
const DIRECTORY_TYPE: u8 = 1;
/// The UnixFS data type of a file root, written in its block as `08 02`.
const FILE_TYPE: u8 = 2;
/// The longest directory block the lab names. Kubo shards a directory into a
/// HAMT once its links' estimated size passes 256KiB; the lab refuses a block
/// over this length instead, which is earlier, so it fails closed.
const DIRECTORY_BLOCK_LIMIT: usize = 262_144;

/// A lab CID, a lab package CID: the SHA-256 digest of a bundle's UnixFS
/// root directory block. It prints as that root's CIDv1 in base32, 59
/// characters that start `bafybei`. It is a prototype, not an admission.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LabCid([u8; 32]);

impl fmt::Display for LabCid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", printed_cid(&cid_bytes(DAG_PB_CODEC, &self.0)))
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
/// keeps the root digest it gives, so a printed value is read in one place
/// and a consumer never copies the printed form. Text that is not a lab CID
/// is refused with [`Refusal::NotALabCid`], the same refusal and text a name
/// check gives. Parsing is not a name check: the value names no bytes until
/// [`check_name`] or [`CheckedBundle::check_name`] compares it.
impl std::str::FromStr for LabCid {
    type Err = Refusal;

    fn from_str(printed: &str) -> Result<Self, Refusal> {
        let digest = lab_cid_digits(printed)?;
        Ok(LabCid(digest))
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
/// binding's check (e2) alone; [`CheckedBundle::wasm`] hands it out. And it keeps the
/// manifest's `name` and `role` from that same check, which
/// [`CheckedBundle::manifest_name`] and [`CheckedBundle::manifest_role`] hand
/// out. It holds a name and bytes, never a decision: it is no trust,
/// admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBundle {
    cid: LabCid,
    entries: Vec<BundleEntry>,
    wasm: bool,
    name: String,
    role: String,
}

/// What the walk does with one entry, decided from the entry's own type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// Walked into. A directory adds no entry itself; the encoder makes its
    /// UnixFS directory from the entry paths.
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
    /// An entry given to the encoder has a path with an empty, `.` or `..`
    /// part, so it names no UnixFS link. The walk never makes one.
    BadPathPart { path: String },
    /// One path given to the encoder is both a file and a directory, as
    /// `a` and `a/b` would be. The walk never makes one.
    FileAndDirectory { path: String },
    /// A listed file ([`encode_listed_files`]) is longer than one raw leaf
    /// holds, 262144 bytes. Its one SHA-256 names a single raw leaf, so a
    /// larger file is named from its bytes, by [`encode_entries`] or
    /// [`lab_cid`]. `length` is the listed size.
    FileOverChunkLimit { path: String, length: usize },
    /// A file needs more leaves than one file root links, 174 of 262144
    /// bytes. The lab names no deeper file tree. `length` is the file's
    /// length.
    FileOverLeafLimit { path: String, length: usize },
    /// A directory's encoded block is longer than 262144 bytes; `.` is the
    /// bundle root. The lab names no HAMT-sharded directory. `length` is the
    /// block's length.
    DirectoryOverBlockLimit { path: String, length: usize },
    /// An entry's open handle is not the kind its folder's listing said: the
    /// entry changed between the listing and the open.
    Changed { path: String },
    /// The walk could not read an entry; `.` is the bundle root. `reason` is
    /// the system's own text. (The field is not named `error`: falsify.py
    /// takes that word with a colon in test output for a harness error, so a
    /// failing assertion that printed this refusal would never count.)
    Unreadable { path: String, reason: String },
    /// The walk met more than its [`Budget`] allows. `limit` names which
    /// of the four limits; `path` is the entry at which it was passed.
    /// Nothing past the limit was read.
    OverBudget { limit: &'static str, path: String },
    /// A name check, or [`LabCid`]'s parse, was given a claim that is not a
    /// lab CID: not `b` and the canonical lowercase base32 of a CIDv1 dag-pb
    /// sha2-256 directory root (`01 70 12 20` and 32 bytes). The claim is
    /// kept only to say what was refused.
    NotALabCid { claimed: String },
    /// A name check was given a lab CID the bundle's bytes do not give.
    /// `actual` is the lab CID of the bytes; the claim is kept only to say
    /// what was refused.
    NameMismatch { actual: LabCid, claimed: String },
    /// The signer DID is not one canonical Ed25519 `did:key`. `reason` is the
    /// decoder's own text.
    #[cfg(feature = "lab")]
    MalformedSignerDid { did: String, reason: String },
    /// The signer DID is not an exact member of the explicit accepted list.
    #[cfg(feature = "lab")]
    SignerNotAccepted { did: String },
    /// The Ed25519 signature does not verify over the signed name. A wrong
    /// key, a changed signature and a name moved onto other bytes all meet
    /// this one check.
    #[cfg(feature = "lab")]
    SignatureDoesNotVerify { did: String, name: String },
    /// A package record binds a CID that is not the checked bundle's. `record`
    /// is the record's CID, kept only to say what was refused; `bundle` is the
    /// lab CID of the checked bytes.
    #[cfg(feature = "lab")]
    RecordNamesAnotherCid { record: String, bundle: LabCid },
    /// A variant list holds no variant. `list` says whose: `binding` (the
    /// binding's pairs) or `given` (the pairs given to sign or verify).
    #[cfg(feature = "lab")]
    NoVariants { list: &'static str },
    /// A variant list holds a label that is not one of [`VARIANT_PLATFORMS`].
    #[cfg(feature = "lab")]
    UnknownPlatform { list: &'static str, label: String },
    /// A variant list holds one label twice.
    #[cfg(feature = "lab")]
    DuplicatePlatform { list: &'static str, label: String },
    /// The platforms given are not the binding's platforms. Both lists are
    /// sorted in byte order.
    #[cfg(feature = "lab")]
    PlatformsDiffer {
        binding: Vec<String>,
        given: Vec<String>,
    },
    /// A binding names, for `platform`, a CID that is not the given bundle's.
    /// `binding` is the binding's CID, kept only to say what was refused;
    /// `bundle` is the lab CID of the checked bytes given for that platform.
    #[cfg(feature = "lab")]
    VariantNamesAnotherCid {
        platform: String,
        binding: String,
        bundle: LabCid,
    },
    /// A binding names a recipe CID that is not the lab CID of the recipe
    /// bytes given. `binding` is the binding's CID; `recipe` is the bytes'.
    #[cfg(feature = "lab")]
    RecipeNamesAnotherCid { binding: String, recipe: LabCid },
    /// A variant list holds the portable label [`PORTABLE_PLATFORM`] and
    /// another label. `labels` is the whole list, sorted in byte order.
    #[cfg(feature = "lab")]
    PortableNotAlone {
        list: &'static str,
        labels: Vec<String>,
    },
    /// A bundle whose manifest `type` is `wasm` is bound under `platform`, a
    /// label that is not [`PORTABLE_PLATFORM`]. `bundle` is its lab CID.
    #[cfg(feature = "lab")]
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
            Refusal::BadPathPart { path } => write!(
                f,
                "the path {path:?} has an empty, . or .. part: each part names one UnixFS link"
            ),
            Refusal::FileAndDirectory { path } => write!(
                f,
                "{path} is both a file and a directory: a bundle path names one or the other"
            ),
            Refusal::FileOverChunkLimit { path, length } => write!(
                f,
                "{path} is {length} bytes, over the {CHUNK_SIZE}-byte limit of one raw leaf: a listed file's one SHA-256 names a single raw leaf, so a larger file is named from its bytes (encode_entries or lab_cid)"
            ),
            Refusal::FileOverLeafLimit { path, length } => write!(
                f,
                "{path} is {length} bytes, over the {MAX_FILE_LINKS}-leaf limit of one file root ({} bytes): the lab names no deeper file tree",
                MAX_FILE_LINKS * CHUNK_SIZE
            ),
            Refusal::DirectoryOverBlockLimit { path, length } => write!(
                f,
                "the directory {path} encodes to {length} bytes, over the {DIRECTORY_BLOCK_LIMIT}-byte block limit: the lab names no HAMT-sharded directory"
            ),
            Refusal::Changed { path } => write!(f, "{path} changed while the bundle was named"),
            Refusal::Unreadable { path, reason } => write!(f, "could not read {path}: {reason}"),
            Refusal::OverBudget { limit, path } => {
                write!(f, "{path} passes the walk's limit on {limit}")
            }
            Refusal::NotALabCid { claimed } => write!(
                f,
                "the claim {claimed:?} is not a lab CID: a lab package CID is a 59-character CIDv1 bafybei... directory root"
            ),
            Refusal::NameMismatch { actual, claimed } => {
                write!(f, "bundle bytes name {actual}; the claim is {claimed}")
            }
            #[cfg(feature = "lab")]
            Refusal::MalformedSignerDid { did, reason } => write!(
                f,
                "signer DID {did} is not a canonical Ed25519 did:key: {reason}"
            ),
            #[cfg(feature = "lab")]
            Refusal::SignerNotAccepted { did } => {
                write!(f, "signer {did} is not in the accepted list")
            }
            #[cfg(feature = "lab")]
            Refusal::SignatureDoesNotVerify { did, name } => {
                write!(f, "signature by {did} does not verify over {name}")
            }
            #[cfg(feature = "lab")]
            Refusal::RecordNamesAnotherCid { record, bundle } => {
                write!(f, "record names {record}; the bundle names {bundle}")
            }
            #[cfg(feature = "lab")]
            Refusal::NoVariants { list } => write!(
                f,
                "the {list} variant list is empty: a binding holds at least one variant"
            ),
            #[cfg(feature = "lab")]
            Refusal::UnknownPlatform { list, label } => write!(
                f,
                "the {list} variant list holds the platform {label:?}, which is not one of {}",
                VARIANT_PLATFORMS.join(", ")
            ),
            #[cfg(feature = "lab")]
            Refusal::DuplicatePlatform { list, label } => write!(
                f,
                "the {list} variant list holds the platform {label} twice: one CID per platform"
            ),
            #[cfg(feature = "lab")]
            Refusal::PlatformsDiffer { binding, given } => write!(
                f,
                "the binding holds the platforms {binding:?}; the given variants are {given:?}"
            ),
            #[cfg(feature = "lab")]
            Refusal::VariantNamesAnotherCid {
                platform,
                binding,
                bundle,
            } => write!(
                f,
                "the binding names {binding} for {platform}; the bundle given for {platform} names {bundle}"
            ),
            #[cfg(feature = "lab")]
            Refusal::RecipeNamesAnotherCid { binding, recipe } => write!(
                f,
                "the binding names the recipe {binding}; the recipe bytes name {recipe}"
            ),
            #[cfg(feature = "lab")]
            Refusal::PortableNotAlone { list, labels } => write!(
                f,
                "the {list} variant list holds the labels {labels:?}: the portable label {PORTABLE_PLATFORM} stands alone"
            ),
            #[cfg(feature = "lab")]
            Refusal::WasmNotPortable { platform, bundle } => write!(
                f,
                "the bundle {bundle} is a WASM app bound under {platform}: a WASM app has one portable variant, bound under {PORTABLE_PLATFORM}"
            ),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether this build holds the lab's own refusals (signatures, records and
/// platform variants). They are compiled only under the `lab` feature, which
/// only `lab/capsule-identity` turns on. A production crate asserts this is
/// `false` at compile time, so that it cannot be built with them.
pub const LAB_REFUSALS: bool = cfg!(feature = "lab");

/// The most one walk may take in. Each limit is checked while the walk
/// lists, before the thing that would pass it is read, entered or kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Files and folders under the root, counted as they are listed.
    pub max_entries: usize,
    /// The sizes of all files, each taken from its open handle before the
    /// file is read; a file is read no further than that size.
    pub max_total_bytes: u64,
    /// Parts in an entry's path: `a/b/c.txt` has three. A folder whose
    /// entries would have more is not listed.
    pub max_depth: usize,
    /// Bytes in an entry's whole path under the root.
    pub max_path_bytes: usize,
}

impl Budget {
    /// No limit: the walk as [`checked_bundle`] has always made it.
    pub const UNLIMITED: Budget = Budget {
        max_entries: usize::MAX,
        max_total_bytes: u64::MAX,
        max_depth: usize::MAX,
        max_path_bytes: usize::MAX,
    };
}

/// What one walk has taken in so far, held against its [`Budget`].
struct Tally {
    budget: Budget,
    entries: usize,
    bytes: u64,
}

impl Tally {
    fn new(budget: Budget) -> Self {
        Tally {
            budget,
            entries: 0,
            bytes: 0,
        }
    }

    /// One listed entry, before the listing keeps it.
    fn entry(&mut self, path: &str) -> Result<(), Refusal> {
        self.entries += 1;
        if self.entries > self.budget.max_entries {
            return Err(over("entries", path));
        }
        if path.len() > self.budget.max_path_bytes {
            return Err(over("path bytes", path));
        }
        Ok(())
    }

    /// A folder, before it is listed: its entries would be one part deeper.
    fn folder(&self, path: &str) -> Result<(), Refusal> {
        if path.split('/').count() >= self.budget.max_depth {
            return Err(over("depth", path));
        }
        Ok(())
    }

    /// A file's size, before the file is read.
    fn file(&mut self, size: u64, path: &str) -> Result<(), Refusal> {
        self.bytes = self.bytes.saturating_add(size);
        if self.bytes > self.budget.max_total_bytes {
            return Err(over("total bytes", path));
        }
        Ok(())
    }
}

fn over(limit: &'static str, path: &str) -> Refusal {
    Refusal::OverBudget {
        limit,
        path: path.to_owned(),
    }
}

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
/// whether that check found `type` to be `wasm` and the manifest's `name`.
/// This is the one walk and the one manifest check. A refusal returns no
/// value.
pub fn checked_bundle_observed(
    bundle: &Path,
    observe: impl FnMut(Moment, &str),
) -> Result<CheckedBundle, Refusal> {
    checked_bundle_within_observed(bundle, Budget::UNLIMITED, observe)
}

/// [`checked_bundle`] under a [`Budget`]: the same walk and the same manifest
/// check, refused as [`Refusal::OverBudget`] as soon as a limit is passed.
pub fn checked_bundle_within(bundle: &Path, budget: Budget) -> Result<CheckedBundle, Refusal> {
    checked_bundle_within_observed(bundle, budget, |_, _| {})
}

/// [`checked_bundle_observed`] under a [`Budget`]. This is the one walk; the
/// other entry points call it.
pub fn checked_bundle_within_observed(
    bundle: &Path,
    budget: Budget,
    mut observe: impl FnMut(Moment, &str),
) -> Result<CheckedBundle, Refusal> {
    let entries = collect_entries(bundle, &mut observe, &mut Tally::new(budget))?;
    let manifest = entries
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or(Refusal::NoManifest)?;
    let (wasm, name, role) = check_manifest(&manifest.content)?;
    encode_entries(&entries)
        // The value keeps the very entries its lab CID names: no second read.
        .map(|cid| CheckedBundle {
            cid,
            entries,
            wasm,
            name,
            role,
        })
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

    /// The `name` of the bundle's `capsule.json`, as the one manifest check
    /// read it from the bytes in [`CheckedBundle::entries`]. It is identity
    /// data, not a decision.
    pub fn manifest_name(&self) -> &str {
        &self.name
    }

    /// The bytes of one bundle file, as the one walk read them from their
    /// checked handle.
    ///
    /// `path` is a bundle-relative, `/`-separated path. A caller that needs a
    /// file takes these bytes, so a change on disk after the walk cannot reach
    /// them and no second folder read runs. `None` means the walk read no such
    /// file. The bytes are identity data under the signed lab CID, not a
    /// decision.
    pub fn entry(&self, path: &str) -> Option<&[u8]> {
        self.entries
            .iter()
            .find(|entry| entry.path == path)
            .map(|entry| entry.content.as_slice())
    }

    /// The `role` of the bundle's `capsule.json`, as the one manifest check
    /// read it from the bytes in [`CheckedBundle::entries`], written the way
    /// the manifest wrote it. It is identity data, not a decision.
    pub fn manifest_role(&self) -> &str {
        &self.role
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

    /// Whether the one manifest check found `type` to be `wasm`.
    pub fn wasm(&self) -> bool {
        self.wasm
    }
}

/// The compare both name checks make: a lab CID whose root digest is not the
/// claim's is refused with both values. `claimed` is the whole claim, kept
/// only to say what was refused.
fn compare_name(actual: LabCid, claimed_digits: [u8; 32], claimed: &str) -> Result<(), Refusal> {
    if actual.0 != claimed_digits {
        return Err(Refusal::NameMismatch {
            actual,
            claimed: claimed.to_owned(),
        });
    }
    Ok(())
}

/// The root digest of a claimed lab CID: the one claim check. The claim must
/// be `b` and base32 whose bytes are the CIDv1 bytes of a dag-pb sha2-256
/// root (`01 70 12 20` and 32 bytes), so a leaf CID or a CIDv0 is refused.
/// Then those bytes must print as exactly the claim, so a second spelling of
/// them (a character more, or unused low bits set in the last character) is
/// refused too. Any other text is not a lab CID.
fn lab_cid_digits(claimed: &str) -> Result<[u8; 32], Refusal> {
    let not_a_lab_cid = || Refusal::NotALabCid {
        claimed: claimed.to_owned(),
    };
    let cid = claimed
        .strip_prefix('b')
        .and_then(decode_base32)
        .ok_or_else(not_a_lab_cid)?;
    let root: [u8; 32] = cid
        .get(cid.len().saturating_sub(32)..)
        .and_then(|digest| digest.try_into().ok())
        .ok_or_else(not_a_lab_cid)?;
    if cid != cid_bytes(DAG_PB_CODEC, &root) {
        return Err(not_a_lab_cid());
    }
    if printed_cid(&cid) != claimed {
        return Err(not_a_lab_cid());
    }
    Ok(root)
}

// A lab copy of the CIDv1 bytes and of their text, `b` and RFC 4648 base32
// (lowercase, no padding), as the multibase and CID specifications write
// them. The Runtime's `cid` crate lives only in `elastos-server` and
// `elastos-namespace`, which the lab does not link, and a new crate here would
// stale the locks of the two lab crates that path-depend on this one. So the
// lab keeps this one marked copy: `cid_bytes`, one encoder and one decoder.

/// The base32 alphabet of RFC 4648, lowercase.
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The CIDv1 bytes of a block with `codec` whose SHA-256 is `digest`: the
/// version, the codec, the multihash code and length, and the digest. Every
/// varint in them is one byte.
fn cid_bytes(codec: u8, digest: &[u8; 32]) -> Vec<u8> {
    let mut cid = vec![CID_VERSION, codec, SHA2_256, SHA2_256_LENGTH];
    cid.extend_from_slice(digest);
    cid
}

/// The printed form of CID bytes, the one encoder: `b`, then each 5 bits of
/// the bytes as one character of [`BASE32_ALPHABET`], the last group padded
/// with zero bits, and no `=` padding.
fn printed_cid(cid: &[u8]) -> String {
    let mut text = String::from("b");
    let (mut bits, mut held) = (0u32, 0u32);
    for &byte in cid {
        bits = (bits << 8) | u32::from(byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            text.push(char::from(BASE32_ALPHABET[(bits >> held) as usize & 31]));
        }
        bits &= (1 << held) - 1;
    }
    if held > 0 {
        text.push(char::from(
            BASE32_ALPHABET[(bits << (5 - held)) as usize & 31],
        ));
    }
    text
}

/// The bytes of base32 text after its `b`, the one decoder; `None` when a
/// character is not in [`BASE32_ALPHABET`]. Bits left over after the last
/// whole byte are dropped here; the claim check refuses a claim that sets
/// them, because it prints the value again and compares.
fn decode_base32(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let (mut bits, mut held) = (0u32, 0u32);
    for character in text.bytes() {
        let value = BASE32_ALPHABET.iter().position(|&one| one == character)?;
        bits = (bits << 5) | value as u32;
        held += 5;
        if held >= 8 {
            held -= 8;
            bytes.push((bits >> held) as u8);
        }
        bits &= (1 << held) - 1;
    }
    Some(bytes)
}

/// One file of a closure listing: its bundle path, its length in bytes and
/// the SHA-256 of its bytes. A raw leaf needs nothing else, so a listing of
/// these is enough to name a bundle of single-block files. A file over one
/// leaf is not: its file root needs each leaf's SHA-256, so it is named from
/// its bytes by [`encode_entries`].
///
/// A listed file names bytes only if its `sha256` and `size` are those of
/// the bytes: the caller's walk owns that. The encoder reads no file and
/// checks no manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedFile {
    pub path: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// The lab CID of `entries`, given in any order: each entry's node made from
/// its bytes by `file_node` (one raw leaf, or a balanced file root over its
/// leaves; a file over 174 leaves is refused), then `encode_tree`, the one
/// tree builder, which [`encode_listed_files`] shares. Leaves, file roots and
/// directory blocks all hash with the one naming hash, `naming_hash`.
pub fn encode_entries(entries: &[BundleEntry]) -> Result<LabCid, Refusal> {
    let mut files = Vec::new();
    for entry in entries {
        files.push((entry.path.as_str(), file_node(entry)?));
    }
    encode_tree(files)
}

/// The lab CID of a closure listing, given in any order. It reads no file
/// and checks no manifest. The lab CID names the bytes only if each file's
/// `sha256` and `size` are those of its bytes; the caller's walk owns that,
/// as [`checked_bundle`]'s walk does for [`encode_entries`].
///
/// Each file is one raw leaf, made by the leaf rule [`encode_entries`] uses:
/// a `size` over [`CHUNK_SIZE`] bytes is refused, because one SHA-256 names
/// a single raw leaf and a file root needs each leaf's; its CID is CIDv1,
/// raw codec, its `sha256`, with its `size` as Tsize. Then `encode_tree`, the
/// one tree builder: the paths make the directories, and a path with an
/// empty, `.` or `..` part, two files with one path, and one path that is
/// both a file and a directory are refused. Each directory, deepest first,
/// becomes one dag-pb block whose links are sorted by name bytes, a block
/// over [`DIRECTORY_BLOCK_LIMIT`] bytes is refused, and the root block's
/// SHA-256 is the lab CID.
pub fn encode_listed_files(files: &[ListedFile]) -> Result<LabCid, Refusal> {
    let mut leaves = Vec::new();
    for file in files {
        if file.size > CHUNK_SIZE as u64 {
            return Err(Refusal::FileOverChunkLimit {
                path: file.path.clone(),
                length: usize::try_from(file.size).unwrap_or(usize::MAX),
            });
        }
        let (cid, tsize) = raw_leaf(&file.sha256, file.size);
        leaves.push((file.path.as_str(), Child::File { cid, tsize }));
    }
    encode_tree(leaves)
}

/// The one tree builder both public calls feed: it puts each file's node at
/// its bundle path with `Directory::insert`, then encodes the root with
/// `encode_directory`. The root block's SHA-256 is the lab CID.
fn encode_tree(files: Vec<(&str, Child)>) -> Result<LabCid, Refusal> {
    let mut root = Directory::default();
    for (path, file) in files {
        root.insert(path, file)?;
    }
    let (digest, _) = encode_directory(&root, "", &naming_hash)?;
    Ok(LabCid(digest))
}

/// The node a directory links for `entry`, made from its bytes: one raw leaf
/// for at most [`CHUNK_SIZE`] bytes (an empty file is an empty leaf), else
/// the balanced file root over its leaves.
fn file_node(entry: &BundleEntry) -> Result<Child, Refusal> {
    let content = &entry.content;
    let (cid, tsize) = if content.len() <= CHUNK_SIZE {
        raw_leaf(&naming_hash(content), content.len() as u64)
    } else {
        file_root(&entry.path, content)?
    };
    Ok(Child::File { cid, tsize })
}

/// A raw leaf's CID bytes and Tsize: CIDv1, raw codec and `sha256`, the
/// SHA-256 of its block, and its length `size`. Every leaf is made here: a
/// listed file's, a one-leaf file's and each leaf under a file root.
fn raw_leaf(sha256: &[u8; 32], size: u64) -> (Vec<u8>, u64) {
    (cid_bytes(RAW_CODEC, sha256), size)
}

/// The CID bytes and Tsize of the balanced file root of `content`, the bytes
/// of the file at `path`, which is over one leaf. The bytes are split into
/// [`CHUNK_SIZE`]-byte raw leaves, the last one shorter, all linked from one
/// dag-pb block, so the tree has one level. A file of more than
/// [`MAX_FILE_LINKS`] leaves would need a second level and is refused with
/// its path and length. The root's Tsize is its block's length plus its
/// leaves' lengths.
fn file_root(path: &str, content: &[u8]) -> Result<(Vec<u8>, u64), Refusal> {
    if content.len().div_ceil(CHUNK_SIZE) > MAX_FILE_LINKS {
        return Err(Refusal::FileOverLeafLimit {
            path: path.to_owned(),
            length: content.len(),
        });
    }
    let leaves: Vec<Link<'_>> = content
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let (cid, tsize) = raw_leaf(&naming_hash(chunk), chunk.len() as u64);
            Link {
                name: "",
                cid,
                tsize,
            }
        })
        .collect();
    let block = file_root_block(&leaves, content.len() as u64);
    let tsize = block.len() as u64 + leaves.iter().map(|leaf| leaf.tsize).sum::<u64>();
    Ok((cid_bytes(DAG_PB_CODEC, &naming_hash(&block)), tsize))
}

/// The one naming hash: the SHA-256 of a leaf, of a file root block or of a
/// directory block.
fn naming_hash(block: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(block);
    hasher.finalize().into()
}

/// A directory as the encoder builds it: each child with its name, in the
/// order the entries were given. Its block sorts them.
#[derive(Default)]
struct Directory {
    children: Vec<(String, Child)>,
}

/// One child of a [`Directory`].
enum Child {
    /// A file's node, a raw leaf or a file root: its CID bytes and its Tsize.
    File { cid: Vec<u8>, tsize: u64 },
    /// A directory below this one.
    Directory(Directory),
}

impl Directory {
    /// Put the file node `file` at the bundle path `path`, making each directory
    /// on the way. A path with an empty, `.` or `..` part is refused; so is
    /// a path already given, and a path that is a file and a directory, in
    /// either order.
    fn insert(&mut self, path: &str, file: Child) -> Result<(), Refusal> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
            return Err(Refusal::BadPathPart {
                path: path.to_owned(),
            });
        }
        let (name, folders) = parts.split_last().expect("a split gives one part");
        let mut directory = self;
        for (depth, part) in folders.iter().enumerate() {
            let at = match directory.position(part) {
                Some(at) => at,
                None => {
                    let made = Child::Directory(Directory::default());
                    directory.children.push(((*part).to_owned(), made));
                    directory.children.len() - 1
                }
            };
            directory = match &mut directory.children[at].1 {
                Child::Directory(inner) => inner,
                Child::File { .. } => {
                    return Err(Refusal::FileAndDirectory {
                        path: parts[..=depth].join("/"),
                    })
                }
            };
        }
        match directory.position(name).map(|at| &directory.children[at].1) {
            None => {
                directory.children.push(((*name).to_owned(), file));
                Ok(())
            }
            Some(Child::File { .. }) => Err(Refusal::DuplicatePath {
                path: path.to_owned(),
            }),
            Some(Child::Directory(_)) => Err(Refusal::FileAndDirectory {
                path: path.to_owned(),
            }),
        }
    }

    /// Where the child named `name` is, if this directory has one.
    fn position(&self, name: &str) -> Option<usize> {
        self.children.iter().position(|(child, _)| child == name)
    }
}

/// One link of a directory block or a file root: the child's name (empty
/// under a file root), CID bytes and Tsize.
struct Link<'a> {
    name: &'a str,
    cid: Vec<u8>,
    tsize: u64,
}

/// The sha2-256 digest and the Tsize of `directory`'s block, at the bundle
/// path `path` (empty for the root). Each child directory is encoded first,
/// and its link's Tsize is its block's length plus its links' Tsizes. The
/// links are sorted by name bytes. A block over [`DIRECTORY_BLOCK_LIMIT`]
/// bytes is refused with its path. `sha256` is the one naming hash.
fn encode_directory(
    directory: &Directory,
    path: &str,
    sha256: &dyn Fn(&[u8]) -> [u8; 32],
) -> Result<([u8; 32], u64), Refusal> {
    let mut links = Vec::new();
    for (name, child) in &directory.children {
        let (cid, tsize) = match child {
            Child::File { cid, tsize } => (cid.clone(), *tsize),
            Child::Directory(inner) => {
                let inner_path = if path.is_empty() {
                    name.clone()
                } else {
                    format!("{path}/{name}")
                };
                let (digest, tsize) = encode_directory(inner, &inner_path, sha256)?;
                (cid_bytes(DAG_PB_CODEC, &digest), tsize)
            }
        };
        links.push(Link { name, cid, tsize });
    }
    links.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let block = directory_block(&links);
    if block.len() > DIRECTORY_BLOCK_LIMIT {
        return Err(Refusal::DirectoryOverBlockLimit {
            path: shown(path),
            length: block.len(),
        });
    }
    let tsize = block.len() as u64 + links.iter().map(|link| link.tsize).sum::<u64>();
    Ok((sha256(&block), tsize))
}

/// A directory's dag-pb block: its links (`put_links`), then the UnixFS data
/// as field 1, which is only its type (field 1, a varint): `08 01`, a
/// directory.
fn directory_block(links: &[Link<'_>]) -> Vec<u8> {
    let mut block = Vec::new();
    put_links(&mut block, links);
    put_length_delimited(&mut block, 1, &[1 << 3, DIRECTORY_TYPE]);
    block
}

/// A file root's dag-pb block: its leaves as links (`put_links`, each name
/// empty), then the UnixFS data as field 1: its type `08 02`, a file, the
/// file's `length` as filesize (field 3, `0x18`), and each leaf's length as
/// one blocksize (field 4, `0x20`, one tag per value, not packed). The data
/// has no Data field (field 2): the bytes are in the leaves.
fn file_root_block(leaves: &[Link<'_>], length: u64) -> Vec<u8> {
    let mut block = Vec::new();
    put_links(&mut block, leaves);
    let mut data = vec![1 << 3, FILE_TYPE];
    data.push(3 << 3);
    put_varint(&mut data, length);
    for leaf in leaves {
        data.push(4 << 3);
        put_varint(&mut data, leaf.tsize);
    }
    put_length_delimited(&mut block, 1, &data);
    block
}

/// The links of a dag-pb block, each in the order given, as protobuf field 2
/// holding the child's CID (field 1), its name (field 2, so an empty name is
/// `12 00`) and its Tsize (field 3, a varint). Directory blocks and file
/// roots write their links here alone.
fn put_links(block: &mut Vec<u8>, links: &[Link<'_>]) {
    for link in links {
        let mut pb_link = Vec::new();
        put_length_delimited(&mut pb_link, 1, &link.cid);
        put_length_delimited(&mut pb_link, 2, link.name.as_bytes());
        pb_link.push(3 << 3);
        put_varint(&mut pb_link, link.tsize);
        put_length_delimited(block, 2, &pb_link);
    }
}

/// Protobuf field `field` of wire type 2: its tag, the length of `bytes` as a
/// varint, and `bytes`.
fn put_length_delimited(out: &mut Vec<u8>, field: u8, bytes: &[u8]) {
    out.push((field << 3) | 2);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// An unsigned protobuf varint: 7 bits per byte, low bits first, the high
/// bit set on every byte but the last. A length or a Tsize can take more
/// than one byte.
fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
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
    tally: &mut Tally,
) -> Result<Vec<BundleEntry>, Refusal> {
    let root = open_checked(CWD, bundle, EntryKind::Directory, "")?;
    let listing = list_folder(root.as_fd(), "", tally)?;
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
            tally.folder(&path)?;
            let listing = list_folder(handle.as_fd(), &path, tally)?;
            folders.push(Folder { handle, listing });
        } else {
            let content = read_file(handle, &path, tally)?;
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
    tally: &mut Tally,
) -> Result<std::vec::IntoIter<Listed>, Refusal> {
    let mut listing = Vec::new();
    for item in Dir::read_from(folder).map_err(|error| unreadable(prefix, error))? {
        let item = item.map_err(|error| unreadable(prefix, error))?;
        let name = item.file_name();
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let path = entry_path(prefix, OsStr::from_bytes(name.to_bytes()))?;
        tally.entry(&path)?;
        listing.push(Listed {
            path,
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
fn read_file(handle: OwnedFd, path: &str, tally: &mut Tally) -> Result<Vec<u8>, Refusal> {
    let mut content = Vec::new();
    if tally.budget == Budget::UNLIMITED {
        File::from(handle)
            .read_to_end(&mut content)
            .map_err(|error| unreadable(path, error))?;
        return Ok(content);
    }
    // Under a budget the size comes from the open handle and is counted
    // before a byte is read, and the read stops at that size.
    let size = fstat(&handle)
        .map_err(|error| unreadable(path, error))?
        .st_size as u64;
    tally.file(size, path)?;
    File::from(handle)
        .take(size)
        .read_to_end(&mut content)
        .map_err(|error| unreadable(path, error))?;
    if content.len() as u64 != size {
        return Err(Refusal::Changed {
            path: path.to_owned(),
        });
    }
    Ok(content)
}

/// The Runtime's own two checks on `capsule.json`, the same two calls it
/// makes on a fetched bundle's manifest: parse it as `CapsuleManifest`
/// (which refuses an unknown field), then `validate()`. The lab adds no rule.
/// It returns whether the parsed manifest's `type` is `wasm`, and the
/// manifest's `name` and `role`, all read from that one parse: nothing else
/// parses `capsule.json`.
fn check_manifest(bytes: &[u8]) -> Result<(bool, String, String), Refusal> {
    let manifest: CapsuleManifest = serde_json::from_slice(bytes)
        .map_err(|error| Refusal::ManifestUnparsed(error.to_string()))?;
    let wasm = manifest.capsule_type == CapsuleType::Wasm;
    // `CapsuleRole::as_str` is total: every role parses to its own spelling,
    // so this conversion has no failure to default.
    let role = manifest.role.as_str().to_owned();
    manifest.validate().map_err(Refusal::ManifestInvalid)?;
    Ok((wasm, manifest.name, role))
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
