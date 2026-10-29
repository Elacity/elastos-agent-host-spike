//! Lab capsule identity: one deterministic **lab CID**, a lab package CID,
//! over a whole capsule bundle (PRINCIPLES 13 and 15).
//!
//! This crate answers two questions: "do these bytes match this name?" and
//! "did this test key sign this lab CID?". It never answers "may this run?":
//! it makes no trust, admission or launch decision and sits in no admission
//! or launch path. Its value is a lab package CID: the CIDv1 SHA-256 UnixFS
//! directory root of the bundle, printed as 59 characters that start
//! `bafybei`. It is a prototype, not an admission, and it defines no shared
//! capsule identity. It is not the Runtime's published name either: the
//! Runtime names a published capsule by the CID its IPFS provider returns
//! for the capsule archive, and an archive hash is a delivery check, not
//! this CID.
//!
//! # The encoding
//!
//! The profile is Kubo v0.40.1's import flags as
//! `capsules/ipfs-provider/src/directory_hash.rs` sends them: CIDv1, sha2-256,
//! raw leaves, chunker `size-262144`, no inline, HAMT fanout 256 and the
//! 256KiB links estimate. The lab CID follows the
//! Kubo v0.40.1 profile, computed by the lab: one offline Kubo v0.40.1
//! hash-only import, with the Runtime's profile flags, was run on this Mac and
//! printed every committed pin, and the lab CID is not called equal to the
//! Runtime's CID or to Kubo's output.
//! This crate pins that profile, with the balanced file layout at any depth,
//! basic directories of one block and HAMT shards on both sides of the
//! threshold:
//!
//! 1. Each regular file of at most 262144 bytes (`CHUNK_SIZE`) is one raw
//!    leaf: its block is the file's bytes (an empty file is an empty block),
//!    its CID is the bytes `01 55 12 20` and the SHA-256 of the block (CID
//!    version 1, raw codec `0x55`, multihash sha2-256 of 32 bytes), and its
//!    Tsize is its length. A larger file is split into 262144-byte raw
//!    leaves, the last one shorter, under a balanced dag-pb file tree
//!    (trickle off): each level groups its nodes left to right into groups of
//!    up to 174 (`MAX_FILE_LINKS`), each full before the next starts, and
//!    wraps each group in one file node, so only a level's last group can be
//!    short and a group of one child is still a node of one link. The depth
//!    is the smallest `d` with `174^d` at least the leaf count: a file of 175
//!    leaves is a root of two depth-1 nodes, 174 leaves then one leaf. A
//!    node's block is, for each child in order, a link with the child's CID,
//!    an empty name and the child's Tsize; then the UnixFS data `08 02` (type
//!    file), the bytes under the node as filesize (field 3) and each child's
//!    file size as one blocksize (field 4, one tag per value). Its CID is
//!    `01 70 12 20` and the SHA-256 of that block, and its Tsize is the
//!    block's length plus its children's Tsizes.
//!    `file_past_174_leaves_keeps_a_second_tree_level` pins
//!    `SECOND_LEVEL_FILE_LAB_CID` (a 175-leaf file) and catches F-CI76a (a
//!    one-child group linked directly) and F-CI76b (a child's Tsize written
//!    as its parent's blocksize).
//! 2. A bundle path such as `browser/app.js` is a directory `browser` that
//!    links `app.js`. A directory's **links estimate** is the sum, over its
//!    direct children, of the child's name in bytes plus 36. An estimate of
//!    at most 262144 (`HAMT_THRESHOLD`) is one basic dag-pb directory block:
//!    one link per child, sorted by name bytes, each as protobuf field 2
//!    holding the child's CID (field 1), its name (field 2) and its Tsize
//!    (field 3, a varint); then the UnixFS data `08 01` (type directory) as
//!    field 1. That block may be longer than 262144 bytes. A greater estimate
//!    is a HAMT shard, and each child directory is judged on its own
//!    estimate. A shard's fanout is 256, so bucket `n` is byte `n` of the
//!    name's murmur3 x64-128 digest (seed 0, first 64 bits big-endian). A
//!    bucket of one child is one link named the bucket's two uppercase hex
//!    digits then the child's name; a bucket of two or more is one link named
//!    only the prefix, to a child shard over the next digest byte, which may
//!    hold one link. Links go out in bucket order. Its UnixFS data is
//!    `08 05`, the bitmap (bucket `i` in byte `31 - i/8` at `1 << (i % 8)`,
//!    leading zero bytes dropped), `28 22` and `30 80 02`. A ninth digest
//!    byte is [`Refusal::HamtTooDeep`], which the inline test
//!    `tests::hamt_depth_exhaustion_is_refused` reaches through the same
//!    builder with a test digest. A directory's CID is `01 70 12 20` and the
//!    SHA-256 of its block (dag-pb codec `0x70`); the Tsize of a link to one
//!    is its block's length plus its children's Tsizes.
//!    `directory_at_the_hamt_threshold_stays_basic`,
//!    `directory_over_the_hamt_threshold_is_a_shard` and
//!    `child_directory_over_the_hamt_threshold_is_a_shard` pin both sides of
//!    the threshold, and `tests::two_names_in_one_bucket_get_a_child_shard`
//!    pins the child shard's one-prefix link.
//! 3. The root is the directory of the bundle's entries. Its CID prints as
//!    `b` and the RFC 4648 base32 of its 36 bytes, lowercase, no padding.
//!
//! No empty directory is emitted. Nothing else enters a block: no folder
//! name, absolute path, mtime, mode, owner or symlink target. The CIDv1 bytes
//! and the base32 text are one marked lab copy in this crate, so the lab adds
//! no crate (the Runtime's `cid` crate lives only in server crates the lab
//! does not link, and a new crate would stale two consumer locks).
//!
//! # One naming path
//!
//! [`checked_bundle`] walks a bundle, checks its root manifest, and hands its
//! entries to [`encode_entries`]. That makes each entry's node from its bytes
//! (one raw leaf, or a file root over its leaves) and hands the nodes to the
//! one tree builder. [`encode_listed_files`], which a caller with its own
//! walk calls directly with a closure listing ([`ListedFile`]: path, size,
//! SHA-256), makes one raw leaf per listed file with the same leaf rule and
//! hands them to the same builder. Together the walk and these two calls are
//! the only code that names a bundle; tests and tools call them and
//! re-implement none. [`lab_cid`] is the same walk and returns only
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
//! field. The record binds a lab CID however it was computed: a folder walk,
//! a checked bundle, entries or a closure listing. [`sign_cid_record`] signs
//! [`domain_separated_digest`] of [`PACKAGE_RECORD_DOMAIN`] and the payload
//! for one [`LabCid`]; it writes nothing. [`verify_cid_record`] checks, in
//! order, the signer's `did:key`, the explicit accepted list, the record's
//! CID against that lab CID, then the Ed25519 signature.
//! [`sign_package_record`] is [`lab_cid`] and then [`sign_cid_record`];
//! [`verify_checked_package_record`] is [`verify_cid_record`] over the
//! checked bundle's CID; [`verify_package_record`] is [`checked_bundle`] and
//! then the checked call. So a record is built, signed and checked in one
//! place each. Both signatures share one
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

// The profile: Kubo v0.40.1's import flags as
// `capsules/ipfs-provider/src/directory_hash.rs` `ADD_OPTIONS` sends them, for
// the balanced file layout at any depth, a basic directory on both sides of
// the 256KiB links estimate and a HAMT shard above it, computed by the lab
// (this crate runs no Kubo). Each
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
/// The most children one file node links (`max-file-links: 174`). A deeper
/// file level starts once a group would hold more, so a file's depth is the
/// smallest `d` with `MAX_FILE_LINKS` to the `d` at least its leaf count.
const MAX_FILE_LINKS: usize = 174;
/// The UnixFS data type of a directory, written in its block as `08 01`.
const DIRECTORY_TYPE: u8 = 1;
/// The UnixFS data type of a file root, written in its block as `08 02`.
const FILE_TYPE: u8 = 2;
/// The UnixFS data type of a HAMT shard, written in its block as `08 05`.
const HAMT_SHARD_TYPE: u8 = 5;
/// The hash type a HAMT shard names, written as `28 22` (murmur3 x64-128).
const HAMT_HASH_TYPE: u8 = 0x22;
/// The buckets one HAMT level holds (`max-hamt-fanout: 256`). Each level
/// takes one further byte of the digest, so a bucket is also one byte.
const HAMT_FANOUT: usize = 256;
/// The bytes of a HAMT digest: murmur3 x64-128's first 64 bits.
const HAMT_DIGEST_BYTES: usize = 8;
/// The length of a HAMT shard's bitmap field before trimming.
const HAMT_BITMAP_BYTES: usize = 32;
/// The size of one directory link outside its name: its CID, its tags and
/// its Tsize. Kubo's `links` estimate adds it to each direct child's name
/// length.
const LINK_OVERHEAD: usize = 36;
/// The links estimate above which a directory is a HAMT shard
/// (`UnixFSHAMTDirectorySizeThreshold: 256KiB`). A directory at this
/// estimate stays basic, even when its block is longer.
const HAMT_THRESHOLD: usize = 262_144;

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
/// binding's check (e2) alone; no accessor hands it out. And it keeps the
/// manifest's `name` from that same check, which
/// [`CheckedBundle::manifest_name`] hands out. It holds a name and bytes,
/// never a decision: it is no trust, admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBundle {
    cid: LabCid,
    entries: Vec<BundleEntry>,
    wasm: bool,
    name: String,
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
    /// The printed lab CID the signature covers, as `LabCid` prints it.
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
    /// A HAMT shard would need a ninth digest byte. The murmur3 digest is
    /// eight bytes, so no deeper level can name these links. `.` is the
    /// bundle root. The builder refuses it instead of looping; the inline
    /// test `tests::hamt_depth_exhaustion_is_refused` reaches it through the
    /// same builder with a test digest.
    HamtTooDeep { path: String },
    /// An entry's open handle is not the kind its folder's listing said: the
    /// entry changed between the listing and the open.
    Changed { path: String },
    /// The walk could not read an entry; `.` is the bundle root. `reason` is
    /// the system's own text. (The field is not named `error`: falsify.py
    /// takes that word with a colon in test output for a harness error, so a
    /// failing assertion that printed this refusal would never count.)
    Unreadable { path: String, reason: String },
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
            Refusal::HamtTooDeep { path } => write!(
                f,
                "the HAMT shard {path} needs a ninth digest byte: the murmur3 digest is {HAMT_DIGEST_BYTES} bytes, so no deeper level names these links"
            ),
            Refusal::Changed { path } => write!(f, "{path} changed while the bundle was named"),
            Refusal::Unreadable { path, reason } => write!(f, "could not read {path}: {reason}"),
            Refusal::NotALabCid { claimed } => write!(
                f,
                "the claim {claimed:?} is not a lab CID: a lab package CID is a 59-character CIDv1 bafybei... directory root"
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
/// whether that check found `type` to be `wasm` and the manifest's `name`.
/// This is the one walk and the one manifest check. A refusal returns no
/// value.
pub fn checked_bundle_observed(
    bundle: &Path,
    mut observe: impl FnMut(Moment, &str),
) -> Result<CheckedBundle, Refusal> {
    let entries = collect_entries(bundle, &mut observe)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or(Refusal::NoManifest)?;
    let (wasm, name) = check_manifest(&manifest.content)?;
    encode_entries(&entries)
        // The value keeps the very entries its lab CID names: no second read.
        .map(|cid| CheckedBundle {
            cid,
            entries,
            wasm,
            name,
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
/// leaves at any depth), then `encode_tree`, the one
/// tree builder, which [`encode_listed_files`] shares. Leaves, file roots and
/// directory blocks all hash with the one naming hash, `naming_hash`.
pub fn encode_entries(entries: &[BundleEntry]) -> Result<LabCid, Refusal> {
    let mut files = Vec::new();
    for entry in entries {
        files.push((entry.path.as_str(), file_node(entry)));
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
/// becomes one dag-pb block whose links are sorted by name bytes, Kubo's
/// links estimate decides whether a directory is that one block or a HAMT
/// shard, and the root block's SHA-256 is the lab CID.
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
/// the balanced file root over its leaves at any depth.
fn file_node(entry: &BundleEntry) -> Child {
    let content = &entry.content;
    let (cid, tsize) = if content.len() <= CHUNK_SIZE {
        raw_leaf(&naming_hash(content), content.len() as u64)
    } else {
        file_root(content)
    };
    Child::File { cid, tsize }
}

/// A raw leaf's CID bytes and Tsize: CIDv1, raw codec and `sha256`, the
/// SHA-256 of its block, and its length `size`. Every leaf is made here: a
/// listed file's, a one-leaf file's and each leaf under a file root.
fn raw_leaf(sha256: &[u8; 32], size: u64) -> (Vec<u8>, u64) {
    (cid_bytes(RAW_CODEC, sha256), size)
}

/// One node of a file's tree: a raw leaf, or a file node over up to
/// [`MAX_FILE_LINKS`] nodes one level down. `tsize` is its block's length plus
/// its children's; `filesize` is the bytes under it, which its parent writes
/// as its blocksize (a raw leaf's two are both its length).
#[derive(Clone)]
struct FileTreeNode {
    cid: Vec<u8>,
    tsize: u64,
    filesize: u64,
}

/// The CID bytes and Tsize of the balanced file root of `content`, the bytes
/// of a file that is over one leaf. The bytes are split into
/// [`CHUNK_SIZE`]-byte raw leaves, the last one shorter. Each level groups its
/// nodes left to right into groups of up to [`MAX_FILE_LINKS`], each full
/// before the next starts, and wraps each group in one dag-pb file node, so
/// only a level's last group can be short and a group of one child is still a
/// node with one link. The depth is the smallest `d` with `MAX_FILE_LINKS^d`
/// at least the leaf count; a file of 175 leaves is a root of two depth-1
/// nodes, 174 leaves then one leaf. The root's Tsize is its block's length
/// plus its children's. A file of one leaf is never here: `file_node` names
/// it as that leaf.
fn file_root(content: &[u8]) -> (Vec<u8>, u64) {
    let mut level: Vec<FileTreeNode> = content
        .chunks(CHUNK_SIZE)
        .map(|chunk| {
            let filesize = chunk.len() as u64;
            let (cid, tsize) = raw_leaf(&naming_hash(chunk), filesize);
            FileTreeNode {
                cid,
                tsize,
                filesize,
            }
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(MAX_FILE_LINKS)
            .map(|group| {
                let filesize = group.iter().map(|child| child.filesize).sum();
                let block = file_root_block(group, filesize);
                let tsize = tsize(&block, group.iter().map(|child| child.tsize));
                FileTreeNode {
                    cid: cid_bytes(DAG_PB_CODEC, &naming_hash(&block)),
                    tsize,
                    filesize,
                }
            })
            .collect();
    }
    let root = level.remove(0);
    (root.cid, root.tsize)
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
/// links are sorted by name bytes. Kubo's links estimate decides the block:
/// at most [`HAMT_THRESHOLD`] is one basic directory block, which may be
/// longer than the threshold; a greater estimate is this HAMT shard over the
/// same links. `sha256` is the one naming hash.
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
    let (block, tsize) = if links_estimate(&links) > HAMT_THRESHOLD {
        let borrowed: Vec<&Link<'_>> = links.iter().collect();
        hamt_shard(&borrowed, path, 0, hamt_digest)?
    } else {
        let block = directory_block(&links);
        let tsize = tsize(&block, links.iter().map(|link| link.tsize));
        (block, tsize)
    };
    Ok((sha256(&block), tsize))
}

/// Kubo's links estimate of one directory: the sum, over its direct children,
/// of the child's name in bytes plus [`LINK_OVERHEAD`]. It is not the block's
/// length and not a child's Tsize: a child directory counts through its own
/// name, and it is judged on its own estimate. An estimate over
/// [`HAMT_THRESHOLD`] is a HAMT shard; one at the threshold stays basic.
fn links_estimate(links: &[Link<'_>]) -> usize {
    links
        .iter()
        .map(|link| link.name.len() + LINK_OVERHEAD)
        .sum()
}

/// The Tsize of a block: its length plus its children's Tsizes. A directory
/// block, a file node and a HAMT shard all use it, so the sum is written
/// once.
fn tsize(block: &[u8], children: impl Iterator<Item = u64>) -> u64 {
    block.len() as u64 + children.sum::<u64>()
}

/// The murmur3 x64-128 digest of a HAMT link name: seed 0, its first 64 bits
/// big-endian. This is the marked lab copy of the one HAMT hash; a separate
/// x64-64 mix gives another value, so it is the wrong function.
/// `hamt_digest("hello")` is `cb d8 a7 b3 41 bd 9b 02`. Level `n` of a shard
/// takes digest byte `n`.
fn hamt_digest(name: &str) -> [u8; HAMT_DIGEST_BYTES] {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;
    let fmix = |mut value: u64| {
        value ^= value >> 33;
        value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
        value ^= value >> 33;
        value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        value ^= value >> 33;
        value
    };
    let bytes = name.as_bytes();
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    for block in 0..bytes.len() / 16 {
        let at = block * 16;
        let mut k1 = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"));
        let mut k2 = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().expect("eight bytes"));
        k1 = k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dc_e729);
        k2 = k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x3849_5ab5);
    }
    let tail = &bytes[bytes.len() / 16 * 16..];
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    for (at, byte) in tail.iter().enumerate() {
        if at < 8 {
            k1 ^= (*byte as u64) << (8 * at);
        } else {
            k2 ^= (*byte as u64) << (8 * (at - 8));
        }
    }
    if tail.len() > 8 {
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
    }
    if !tail.is_empty() {
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    }
    let length = bytes.len() as u64;
    h1 ^= length;
    h2 ^= length;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix(h1).wrapping_add(fmix(h2));
    h1.to_be_bytes()
}

/// One HAMT shard block over `links`, at digest byte `level`, with
/// [`HAMT_FANOUT`] buckets: bucket `n` is the digest's byte `n`. A bucket of
/// one child is one link whose name is the bucket's two uppercase hex digits
/// and then the child's own name, to that child. A bucket of two or more is
/// one link whose name is only the prefix, to a child shard over the next
/// byte, which may itself hold one link. Links go out in bucket order, then
/// the UnixFS data: `08 05`, the bitmap (bucket `i` set in byte `31 - i/8` at
/// mask `1 << (i % 8)`, its leading zero bytes dropped), `28 22` (hash type
/// 0x22) and `30 80 02` (fanout 256). No filesize, blocksizes, mode or mtime.
/// `digest` is [`hamt_digest`] on the product path; a test may give another
/// one to reach the ninth byte.
fn hamt_shard(
    links: &[&Link<'_>],
    path: &str,
    level: usize,
    digest: fn(&str) -> [u8; HAMT_DIGEST_BYTES],
) -> Result<(Vec<u8>, u64), Refusal> {
    if level == HAMT_DIGEST_BYTES {
        return Err(Refusal::HamtTooDeep { path: shown(path) });
    }
    let mut buckets: Vec<Vec<&Link<'_>>> = vec![Vec::new(); HAMT_FANOUT];
    for link in links {
        buckets[digest(link.name)[level] as usize].push(*link);
    }
    let mut bitmap = [0u8; HAMT_BITMAP_BYTES];
    let mut children: Vec<(String, Vec<u8>, u64)> = Vec::new();
    for (bucket, group) in buckets.iter().enumerate() {
        if group.is_empty() {
            continue;
        }
        bitmap[HAMT_BITMAP_BYTES - 1 - bucket / 8] |= 1 << (bucket % 8);
        let prefix = format!("{bucket:02X}");
        match group[..] {
            [child] => children.push((
                format!("{prefix}{}", child.name),
                child.cid.clone(),
                child.tsize,
            )),
            _ => {
                let (block, child_tsize) = hamt_shard(group, path, level + 1, digest)?;
                children.push((
                    prefix,
                    cid_bytes(DAG_PB_CODEC, &naming_hash(&block)),
                    child_tsize,
                ));
            }
        }
    }
    let written: Vec<Link<'_>> = children
        .iter()
        .map(|(name, cid, tsize)| Link {
            name,
            cid: cid.clone(),
            tsize: *tsize,
        })
        .collect();
    let mut block = Vec::new();
    put_links(&mut block, &written);
    let mut data = vec![1 << 3, HAMT_SHARD_TYPE];
    let first = bitmap
        .iter()
        .position(|byte| *byte != 0)
        .expect("a shard holds at least one bucket");
    put_length_delimited(&mut data, 2, &bitmap[first..]);
    data.push(5 << 3);
    data.push(HAMT_HASH_TYPE);
    data.push(6 << 3);
    put_varint(&mut data, HAMT_FANOUT as u64);
    put_length_delimited(&mut block, 1, &data);
    let tsize = tsize(&block, children.iter().map(|(_, _, tsize)| *tsize));
    Ok((block, tsize))
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

/// A file node's dag-pb block, at any depth: its children as links
/// (`put_links`, each name empty), then the UnixFS data as field 1: its type
/// `08 02`, a file, the bytes under it as `filesize` (field 3, `0x18`), and
/// each child's file size as one blocksize (field 4, `0x20`, one tag per
/// value, not packed; a raw leaf's file size is its length, and a file node's
/// is the bytes under it, not its Tsize). The data has no Data field (field
/// 2): the bytes are in the leaves.
fn file_root_block(children: &[FileTreeNode], filesize: u64) -> Vec<u8> {
    let links: Vec<Link<'_>> = children
        .iter()
        .map(|child| Link {
            name: "",
            cid: child.cid.clone(),
            tsize: child.tsize,
        })
        .collect();
    let mut block = Vec::new();
    put_links(&mut block, &links);
    let mut data = vec![1 << 3, FILE_TYPE];
    data.push(3 << 3);
    put_varint(&mut data, filesize);
    for child in children {
        data.push(4 << 3);
        put_varint(&mut data, child.filesize);
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
/// It returns whether the parsed manifest's `type` is `wasm` and the
/// manifest's `name`, both read from that one parse: nothing else parses
/// `capsule.json`.
fn check_manifest(bytes: &[u8]) -> Result<(bool, String), Refusal> {
    let manifest: CapsuleManifest = serde_json::from_slice(bytes)
        .map_err(|error| Refusal::ManifestUnparsed(error.to_string()))?;
    let wasm = manifest.capsule_type == CapsuleType::Wasm;
    manifest.validate().map_err(Refusal::ManifestInvalid)?;
    Ok((wasm, manifest.name))
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
/// domain. [`naming_hash`], which the encoder calls, remains the one naming
/// hash.
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
/// The whole printed lab CID, its `b` prefix included, is the signed name.
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

/// Sign a package record for the lab CID `cid` with `key`.
///
/// This is the one place a record is built and signed. The record's CID is
/// `cid`'s printed form, and `signer_did` is
/// `elastos_identity::encode_signing_key_did` of `key`. The signature is
/// Ed25519 over [`domain_separated_digest`] of [`PACKAGE_RECORD_DOMAIN`] and
/// the record's payload. It writes no file and reads none.
///
/// It signs a name, not bytes: `cid` must come from [`encode_listed_files`],
/// [`encode_entries`], [`lab_cid`] or [`checked_bundle`], so it names the
/// bytes that call read or was given. It grants nothing.
pub fn sign_cid_record(key: &SigningKey, cid: LabCid) -> PackageRecord {
    let cid = cid.to_string();
    let signer_did = signer_did_of(key);
    let mut record = PackageRecord {
        cid,
        signer_did,
        signature: [0; 64],
    };
    record.signature = key.sign(&package_record_message(&record)).to_bytes();
    record
}

/// Sign a package record for `bundle` with `key`.
///
/// This is [`lab_cid`] and then [`sign_cid_record`]; it builds and signs
/// nothing itself. A bundle [`lab_cid`] refuses gets no record, and the
/// refusal is [`lab_cid`]'s own. It writes no file and changes no bundle byte.
pub fn sign_package_record(key: &SigningKey, bundle: &Path) -> Result<PackageRecord, Refusal> {
    let cid = lab_cid(bundle)?;
    Ok(sign_cid_record(key, cid))
}

/// Check `record` against the lab CID `cid`.
///
/// This is the one place a record is checked. The checks run in this order,
/// and the first refusal is the answer:
///
/// 1. `elastos_identity::decode_did_key` on `record.signer_did`, with the name
///    signature's reason.
/// 2. `record.signer_did` is an exact member of `accepted`, with the name
///    signature's reason. An empty list refuses every signer.
/// 3. `record.cid` is `cid`'s printed form. Otherwise it is refused naming
///    both. This reads nothing from disk.
/// 4. Ed25519 verification of `record.signature` over the record's digest,
///    with the key from step 1 and the name signature's reason.
///
/// It checks a signature over a name, not bytes: `cid` must come from
/// [`encode_listed_files`], [`encode_entries`], [`lab_cid`] or
/// [`checked_bundle`]. `Ok(())` means all four passed. It is not a trust,
/// admission or launch value, and it grants nothing.
pub fn verify_cid_record(
    cid: LabCid,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    let key = decode_signer(&record.signer_did)?;
    require_accepted(&record.signer_did, accepted)?;
    require_record_cid(cid, record)?;
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

/// Check `record` against the bytes `checked` holds.
///
/// This is [`verify_cid_record`] over `checked.cid()`, so it holds no check
/// of its own and reads nothing from disk. `Ok(())` grants nothing.
pub fn verify_checked_package_record(
    checked: &CheckedBundle,
    record: &PackageRecord,
    accepted: &[String],
) -> Result<(), Refusal> {
    verify_cid_record(checked.cid(), record, accepted)
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

/// Check (c) of a package record: it binds `cid`'s printed form.
fn require_record_cid(cid: LabCid, record: &PackageRecord) -> Result<(), Refusal> {
    if record.cid != cid.to_string() {
        return Err(Refusal::RecordNamesAnotherCid {
            record: record.cid.clone(),
            bundle: cid,
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

/// The lab CID of a variant recipe: [`encode_entries`], which calls the one
/// encoder, of one entry at [`VARIANT_RECIPE_ENTRY`] holding `recipe`.
/// Nothing here reads the recipe from disk; the caller gives its bytes.
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

/// The one HAMT hash: murmur3 x64-128 of the link name, seed 0, its first 64
/// bits big-endian. `hello` pins the marked copy; the x64-64 mix gives
/// another value, so this assertion catches the wrong function, and
/// F-CI77a catches the wrong byte order.
#[cfg(test)]
#[test]
fn hamt_digest_is_the_marked_murmur3_copy() {
    assert_eq!(
        hamt_digest("hello"),
        [0xcb, 0xd8, 0xa7, 0xb3, 0x41, 0xbd, 0x9b, 0x02],
        "the first 64 bits of murmur3 x64-128 of \"hello\", big-endian"
    );
}

/// The shard builder, which tests reach through the same private function
/// the encoder calls.
#[cfg(test)]
mod tests {
    use super::*;

    /// A protobuf varint of `bytes` at `at`, which moves past it.
    fn read_varint(bytes: &[u8], at: &mut usize) -> u64 {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = bytes[*at];
            *at += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    /// A block's length-delimited fields, each with its number.
    fn length_delimited(block: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut at = 0;
        let mut found = Vec::new();
        while at < block.len() {
            let tag = read_varint(block, &mut at);
            let field = tag >> 3;
            if tag & 7 != 2 {
                read_varint(block, &mut at);
                continue;
            }
            let length = read_varint(block, &mut at) as usize;
            found.push((field, block[at..at + length].to_vec()));
            at += length;
        }
        found
    }

    /// Each link of a block as its name and Tsize, in block order.
    fn links_of(block: &[u8]) -> Vec<(String, u64)> {
        let mut links = Vec::new();
        for (field, link) in length_delimited(block) {
            if field != 2 {
                continue;
            }
            let mut at = 0;
            let mut name = String::new();
            let mut tsize = 0;
            while at < link.len() {
                let tag = read_varint(&link, &mut at);
                let inner = tag >> 3;
                if tag & 7 == 2 {
                    let length = read_varint(&link, &mut at) as usize;
                    if inner == 2 {
                        name = String::from_utf8(link[at..at + length].to_vec())
                            .expect("a link name is UTF-8");
                    }
                    at += length;
                } else {
                    tsize = read_varint(&link, &mut at);
                }
            }
            links.push((name, tsize));
        }
        links
    }

    /// A shard block's UnixFS data field.
    fn unixfs_of(block: &[u8]) -> Vec<u8> {
        for (field, value) in length_delimited(block) {
            if field == 1 {
                return value;
            }
        }
        panic!("the block holds no UnixFS data");
    }

    /// The bitmap field of a shard's UnixFS data.
    fn bitmap_of(data: &[u8]) -> Vec<u8> {
        for (field, value) in length_delimited(data) {
            if field == 2 {
                return value;
            }
        }
        panic!("the UnixFS data holds no bitmap");
    }

    /// Test links with a one-byte CID stand-in and Tsize 0.
    fn link_list<'a>(names: &'a [&'a str]) -> Vec<Link<'a>> {
        names
            .iter()
            .map(|name| Link {
                name,
                cid: vec![CID_VERSION, RAW_CODEC, SHA2_256, SHA2_256_LENGTH, 0],
                tsize: 0,
            })
            .collect()
    }

    #[test]
    fn two_names_in_one_bucket_get_a_child_shard() {
        // The collision pair shares bucket E8 and differs at the next byte.
        // The root shard holds one link named only E8, to a child shard; the
        // child holds each name behind its own prefix.
        let names = ["collision-one", "collision-two-82"];
        let pair = link_list(&names);
        let borrowed: Vec<&Link<'_>> = pair.iter().collect();
        let (block, _) = hamt_shard(&borrowed, ".", 0, hamt_digest).expect("a shard");
        let written = links_of(&block);
        assert_eq!(written.len(), 1, "one bucket is one link");
        assert_eq!(written[0].0, "E8", "the link is named only by its prefix");
        assert!(
            !written[0].0.contains("collision"),
            "the link holds no child's name"
        );
        let (child, child_tsize) =
            hamt_shard(&borrowed, ".", 1, hamt_digest).expect("a child shard");
        assert_eq!(
            written[0].1, child_tsize,
            "the E8 link points at the child shard"
        );
        let child_names: Vec<String> = links_of(&child).into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            child_names,
            ["81collision-one", "90collision-two-82"],
            "the child shard holds each name behind its next-byte prefix"
        );
    }

    #[test]
    fn hamt_depth_exhaustion_is_refused() {
        // A constant digest never splits two links, so the builder walks one
        // level per digest byte and refuses the ninth.
        let names = ["deep-one", "deep-two"];
        let pair = link_list(&names);
        let borrowed: Vec<&Link<'_>> = pair.iter().collect();
        let result = hamt_shard(&borrowed, "deep", 0, |_| [0u8; HAMT_DIGEST_BYTES]);
        assert_eq!(
            result,
            Err(Refusal::HamtTooDeep {
                path: "deep".to_owned()
            })
        );
        let refusal = result.expect_err("a ninth digest byte is refused");
        assert_eq!(
            refusal,
            Refusal::HamtTooDeep {
                path: "deep".to_owned()
            }
        );
        assert_eq!(
            refusal.to_string(),
            "the HAMT shard deep needs a ninth digest byte: the murmur3 digest is 8 bytes, so no deeper level names these links"
        );
    }

    #[test]
    fn hamt_bitmap_drops_leading_zero_bytes() {
        // Two links in buckets 1 and 2: both bits sit in the field's last
        // byte, so 31 leading zero bytes drop. A shard that keeps all 32
        // bytes writes another block and another CID.
        let names = ["a", "bb"];
        let pair = link_list(&names);
        let low = |name: &str| {
            let mut digest = [0u8; HAMT_DIGEST_BYTES];
            digest[0] = name.len() as u8;
            digest
        };
        let borrowed: Vec<&Link<'_>> = pair.iter().collect();
        let (block, _) = hamt_shard(&borrowed, ".", 0, low).expect("a shard");
        let data = unixfs_of(&block);
        assert_eq!(
            data,
            [0x08, 0x05, 0x12, 0x01, 0x06, 0x28, 0x22, 0x30, 0x80, 0x02],
            "type 5, the one-byte bitmap, hash type 0x22 and fanout 256"
        );
        let bitmap = bitmap_of(&data);
        assert_eq!(bitmap, [0b110], "buckets 1 and 2 in the last byte");
        assert!(bitmap.len() < HAMT_BITMAP_BYTES, "{bitmap:?}");
    }
}
