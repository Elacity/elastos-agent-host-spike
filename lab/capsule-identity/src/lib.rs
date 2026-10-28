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
//! raw leaves, chunker `size-262144`, no inline, a HAMT shard only past its
//! links threshold. The lab CID follows the
//! Kubo v0.40.1 profile, computed by the lab: one offline Kubo v0.40.1
//! hash-only cross-check with the Runtime's profile flags was run by hand on
//! this Mac (task 050) and printed every committed pin, and the claim stays
//! these words until Rong or Flint changes them. This crate runs no Kubo
//! and pins that profile at any tree depth, with a basic directory or a HAMT
//! shard as Kubo names it:
//!
//! 1. Each regular file of at most 262144 bytes (`CHUNK_SIZE`) is one raw
//!    leaf: its block is the file's bytes (an empty file is an empty block),
//!    its CID is the bytes `01 55 12 20` and the SHA-256 of the block (CID
//!    version 1, raw codec `0x55`, multihash sha2-256 of 32 bytes), and its
//!    Tsize is its length. A larger file is split into 262144-byte raw
//!    leaves, the last one shorter, under Kubo's balanced dag-pb file tree
//!    (trickle off) at any depth: the depth is the smallest `d >= 1` with
//!    `174^d >= leaves` (`max-file-links` 174). A node at depth 1 links up to
//!    174 leaves; a node at depth `k > 1` links up to 174 nodes of depth
//!    `k - 1`. Nodes are filled left to right, each full before the next, so
//!    only a level's last node can be short, and a last node that holds one
//!    leaf is still a node of one link. Each node's block has, for each child
//!    in order, a link with the child's CID, an empty name and the child's
//!    Tsize; then the UnixFS data `08 02` (type file), the bytes under it
//!    (filesize, field 3) and each child's filesize (blocksizes, field 4, one
//!    tag per value). Its CID is `01 70 12 20` and the SHA-256 of that block,
//!    and its Tsize is the block's length plus its children's Tsizes.
//! 2. A bundle path such as `browser/app.js` is a directory `browser` that
//!    links `app.js`. Each directory's block is dag-pb: one link per child,
//!    sorted by name bytes, each as protobuf field 2 holding the child's CID
//!    (field 1), its name (field 2) and its Tsize (field 3, a varint); then
//!    the UnixFS data `08 01` (type directory) as field 1. A directory's CID
//!    is `01 70 12 20` and the SHA-256 of its block (dag-pb codec `0x70`).
//!    The Tsize of a link to a directory is that directory's block length
//!    plus the Tsizes of its links. A directory is judged on its own direct
//!    children: when the sum over them of each name's byte length and 36 (a
//!    CIDv1 SHA-256) is at most 262144, it is a basic directory, even when
//!    its block is longer. When that links estimate is greater, it is a HAMT
//!    shard: fanout 256, hash murmur3 `New64` (the first 64 bits of
//!    x64-128, seed 0), one digest byte per level. A bucket with one child
//!    is one link named the bucket's two uppercase hex digits and the
//!    child's name; a bucket with two or more is one link named only the
//!    prefix, pointing at a child shard built from the next digest byte. A
//!    ninth byte is refused with [`Refusal::HamtTooDeep`]. The shard's links
//!    go out in bucket order; its UnixFS data is `08 05`, field 2 the
//!    bitmap with bucket `i` in byte `31 - i / 8` at `1 << (i % 8)` and its
//!    leading zero bytes dropped, `28 22` (hash type) and `30 80 02`
//!    (fanout 256). Its CID is `01 70 12 20` and the SHA-256 of its block,
//!    and its Tsize is its block's length plus its links' Tsizes. A child
//!    directory is judged on its own estimate, so a root of a few names
//!    stays basic over a sharded child (task 056:
//!    `directory_at_the_hamt_threshold_stays_basic`,
//!    `directory_over_the_hamt_threshold_is_a_shard`,
//!    `child_directory_over_the_hamt_threshold_is_a_shard` and the
//!    `hello` digest test; falsifiers F-CI56a to F-CI56l, with F-CI18h,
//!    F-CI53a and F-CI53b retargeted).
//! 3. The root is the directory of the bundle's entries. Its CID prints as
//!    `b` and the RFC 4648 base32 of its 36 bytes, lowercase, no padding.
//!
//! A path with a part that starts with `.` (a hidden name, such as the
//! `.DS_Store` macOS Finder writes, or the folder in `.well-known/a.txt`) is
//! refused with [`Refusal::HiddenName`]: Kubo's `add` without `--hidden`,
//! and neither Runtime flag list gives it, leaves such a name out of the
//! CID, so skipping it would leave bytes out of the name, and keeping it
//! would print a name Kubo does not give. The lab names every byte or
//! refuses. A dot inside or at the end of a name (`a.b`, `x.`) is a plain
//! name.
//!
//! A folder that holds no file, at any depth (an empty folder, or one that
//! holds only such folders), is refused with [`Refusal::EmptyFolder`].
//! Kubo's import with the Runtime's flags (`--empty-dirs=false`) leaves out
//! an empty folder but keeps a folder that holds only empty folders (task
//! 052's hand run), so the lab names no folder without a file rather than
//! print a name Kubo may not give. So no empty directory is ever encoded.
//! Only the walk sees folders, so the check is in the walk, once; a caller of
//! the encoder gives file paths, which hold no empty folder.
//!
//! Nothing else enters a block: no folder
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
//! hands them to the same builder. [`encode_chunked_files`] is the same
//! encoder for a file of any size whose caller kept each raw leaf's SHA-256
//! ([`ChunkedFile`]: path, size, the leaves' digests): it makes the leaves
//! and the balanced file root with the builder [`encode_entries`] uses, and
//! checks only that the digest count matches the size. Together the walk and
//! these three calls are the only code that names a bundle; tests and tools
//! call them and re-implement none. [`lab_cid`] is the same walk and returns
//! only
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

use std::borrow::Cow;
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
// files at any tree depth and a basic directory or a HAMT shard, computed by
// the lab (no Kubo runs here). Each
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
/// The most children one node of a file's tree links, at every level
/// (`max-file-links: 174`). A file of more leaves gets a deeper tree.
const MAX_FILE_LINKS: usize = 174;
/// The UnixFS data type of a directory, written in its block as `08 01`.
const DIRECTORY_TYPE: u8 = 1;
/// The UnixFS data type of a file root, written in its block as `08 02`.
const FILE_TYPE: u8 = 2;
/// The largest links estimate of a basic directory (256KiB). A directory
/// whose estimate is greater is a HAMT shard. Kubo shards only when the
/// estimate is greater; an estimate of exactly this value stays basic.
const DIRECTORY_LINKS_LIMIT: usize = 262_144;
/// The bytes a directory link's estimate counts for a child's CID: a CIDv1
/// SHA-256 multihash is 36 bytes.
const CIDV1_SHA256_LENGTH: usize = 36;
/// The UnixFS data type of a HAMT shard, written in its block as `08 05`.
const HAMT_SHARD_TYPE: u8 = 5;
/// The hash type Kubo writes for a HAMT shard, murmur3, as `28 22`.
const HAMT_HASH_TYPE: u64 = 0x22;
/// The HAMT fanout: 256 buckets, so each level takes one digest byte.
const HAMT_FANOUT: u32 = 256;
/// The bytes of a murmur3 digest: one byte per level, at most eight.
const HAMT_DIGEST_BYTES: usize = 8;
/// The bytes of a HAMT shard's bitmap: one bit per bucket.
const HAMT_BITMAP_BYTES: usize = HAMT_FANOUT as usize / 8;

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
    /// An entry given to the encoder has a path with a part that starts with
    /// `.` (and is not `.` or `..`), such as `.DS_Store` or `.well-known/a`.
    /// Kubo's import with the Runtime's flags has no `--hidden`, so it leaves
    /// such a name out of the CID; the lab names every byte or refuses.
    HiddenName { path: String },
    /// A folder below the bundle root holds no file at any depth: it is
    /// empty, or holds only folders that hold no file. Kubo's import with the
    /// Runtime's flags (`--empty-dirs=false`) leaves out an empty folder but
    /// keeps a folder that holds only empty folders, so the lab refuses any
    /// folder with no file rather than print a name Kubo may not give. Only
    /// the walk sees folders; `path` is the folder's bundle path.
    EmptyFolder { path: String },
    /// One path given to the encoder is both a file and a directory, as
    /// `a` and `a/b` would be. The walk never makes one.
    FileAndDirectory { path: String },
    /// A listed file ([`encode_listed_files`]) is longer than one raw leaf
    /// holds, 262144 bytes. Its one SHA-256 names a single raw leaf, so a
    /// larger file is named from its bytes, by [`encode_entries`] or
    /// [`lab_cid`]. `length` is the listed size.
    FileOverChunkLimit { path: String, length: usize },
    /// A chunked file ([`encode_chunked_files`]) holds a number of raw-leaf
    /// digests its size does not give: a file's chunks are [`CHUNK_SIZE`]
    /// bytes with a short last one, and an empty file is one leaf. `expected`
    /// is `max(1, ceil(size / CHUNK_SIZE))`, and `supplied` is the length of
    /// its digest list.
    ChunkCountMismatch {
        path: String,
        size: u64,
        expected: usize,
        supplied: usize,
    },
    /// A HAMT bucket needs a ninth digest byte: the eight bytes of a 64-bit
    /// murmur3 digest are one level each, and this bucket's children still
    /// share all of them. Kubo's hash bits are exhausted here, so the lab
    /// refuses rather than name a deeper shard. Two distinct names with one
    /// 64-bit digest reach it; no test can make one, so this refusal has no
    /// falsifier and no test seam. `path` is the directory's bundle path.
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
            Refusal::HiddenName { path } => write!(
                f,
                "the path {path:?} has a part that starts with .: Kubo's import with the Runtime's flags (no --hidden) leaves a name starting with . out of the CID, and the lab names every byte or refuses"
            ),
            Refusal::EmptyFolder { path } => write!(
                f,
                "the folder {path:?} holds no file: Kubo's import with the Runtime's flags (--empty-dirs=false) leaves out an empty folder but keeps a folder that holds only empty folders, so the lab refuses any folder with no file rather than print a name Kubo may not give"
            ),
            Refusal::FileAndDirectory { path } => write!(
                f,
                "{path} is both a file and a directory: a bundle path names one or the other"
            ),
            Refusal::FileOverChunkLimit { path, length } => write!(
                f,
                "{path} is {length} bytes, over the {CHUNK_SIZE}-byte limit of one raw leaf: a listed file's one SHA-256 names a single raw leaf, so a larger file is named from its bytes (encode_entries or lab_cid)"
            ),
            Refusal::ChunkCountMismatch {
                path,
                size,
                expected,
                supplied,
            } => write!(
                f,
                "{path} is {size} bytes and holds {supplied} chunk digests: its size gives {expected} chunks of at most {CHUNK_SIZE} bytes, one for an empty file"
            ),
            Refusal::HamtTooDeep { path } => write!(
                f,
                "the directory {path} needs a ninth murmur3 byte: {HAMT_DIGEST_BYTES} levels of 256 buckets do not separate its names, and the lab writes no deeper HAMT"
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

/// One file of a closure listing for a file of any size: its bundle path,
/// its length in bytes and the SHA-256 of each of its raw leaves, in
/// file-byte order. The leaves are [`CHUNK_SIZE`]-byte chunks of the file,
/// the last one shorter, so `size` gives each leaf's length; an empty file
/// has one leaf, the empty raw leaf.
///
/// The caller supplies `size` and the digests from the same observed bytes
/// and owns reading and hashing them. [`encode_chunked_files`] reads no
/// payload and checks no manifest: it checks the listing's shape, that each
/// file's digest count is the count its size gives, and names it with the
/// one CID rule. Byte verification stays the caller's job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedFile {
    pub path: String,
    pub size: u64,
    pub chunk_sha256: Vec<[u8; 32]>,
}

/// The lab CID of `entries`, given in any order: each entry's node made from
/// its bytes by `file_node` (one raw leaf, or the balanced file tree over its
/// leaves, at any depth), then `encode_tree`, the one
/// tree builder, which [`encode_listed_files`] and
/// [`encode_chunked_files`] share. Leaves, file roots and directory blocks
/// all hash with the one naming hash, `naming_hash`.
pub fn encode_entries(entries: &[BundleEntry]) -> Result<LabCid, Refusal> {
    let files = entries
        .iter()
        .map(|entry| (entry.path.as_str(), file_node(entry)))
        .collect();
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
/// empty, `.` or `..` part, a path with a part that starts with `.`, two
/// files with one path, and one path that is both a file and a directory
/// are refused. Each directory, deepest first,
/// becomes one dag-pb block whose links are sorted by name bytes, a directory
/// over [`DIRECTORY_LINKS_LIMIT`]'s links estimate is a HAMT shard, and the
/// root block's SHA-256 is the lab CID.
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

/// The lab CID of a closure listing whose files are given as the SHA-256 of
/// each raw leaf, given in any order. It reads no file and checks no
/// manifest, and it parses no manifest.
///
/// Each file's digests make its raw leaves with the leaf rule
/// [`encode_entries`] uses, then the balanced file tree over them, at any
/// depth: one leaf is that leaf, more are grouped as the encoding describes.
/// The leaves' lengths come from `size`: each is [`CHUNK_SIZE`] bytes and the
/// last is shorter, and an empty file is one empty leaf. A count the size
/// does not give is refused with [`Refusal::ChunkCountMismatch`]. Then
/// `encode_tree`, the one tree builder, with the same path refusals
/// [`encode_entries`] gives.
///
/// The caller supplies `size` and the digests from the same observed bytes
/// and owns reading and hashing them; this call checks the listing's shape
/// and names it, and byte verification stays the caller's job.
///
/// # Example
///
/// A multi-leaf listing named by this call, then its name in the existing
/// package record:
///
/// ```
/// # use capsule_identity::{encode_chunked_files, sign_cid_record, ChunkedFile};
/// # fn main() -> Result<(), capsule_identity::Refusal> {
/// # let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
/// let listing = vec![ChunkedFile {
///     path: "images/a.raw".to_owned(),
///     size: 262_145,
///     chunk_sha256: vec![[1; 32], [2; 32]],
/// }];
/// let cid = encode_chunked_files(&listing)?;
/// let record = sign_cid_record(&key, cid);
/// # Ok(())
/// # }
/// ```
pub fn encode_chunked_files(files: &[ChunkedFile]) -> Result<LabCid, Refusal> {
    let mut nodes = Vec::new();
    for file in files {
        let expected = chunk_count(file.size);
        let supplied = file.chunk_sha256.len();
        if supplied as u64 != expected {
            return Err(Refusal::ChunkCountMismatch {
                path: file.path.clone(),
                size: file.size,
                expected: usize::try_from(expected).unwrap_or(usize::MAX),
                supplied,
            });
        }
        let leaves: Vec<FileLeaf> = file
            .chunk_sha256
            .iter()
            .enumerate()
            .map(|(index, sha256)| FileLeaf {
                sha256: *sha256,
                size: chunk_length(file.size, index),
            })
            .collect();
        let (cid, tsize) = file_root_leaves(&leaves);
        nodes.push((file.path.as_str(), Child::File { cid, tsize }));
    }
    encode_tree(nodes)
}

/// How many [`CHUNK_SIZE`]-byte leaves a file of `size` bytes has: one for
/// an empty file, else the whole chunks plus one when the last is short. The
/// division and the remainder cannot overflow.
fn chunk_count(size: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    if size % chunk == 0 {
        (size / chunk).max(1)
    } else {
        size / chunk + 1
    }
}

/// The length of chunk `index` of a file of `size` bytes: [`CHUNK_SIZE`],
/// except that the last one is short.
fn chunk_length(size: u64, index: usize) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    size.saturating_sub(chunk.saturating_mul(index as u64))
        .min(chunk)
}

/// The one tree builder every naming call feeds: it puts each file's node at
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

/// One node of a file's tree, as its parent links it: its CID bytes, its
/// Tsize (its block and everything under it) and its filesize (the file's
/// bytes under it). A raw leaf's Tsize and filesize are both its length.
struct FileTreeNode {
    cid: Vec<u8>,
    tsize: u64,
    filesize: u64,
}

/// One raw leaf of a file, as the tree builder takes it: the SHA-256 of its
/// block and its length. [`encode_chunked_files`] gets these from a caller's
/// digests and size; [`file_root`] gets them from the file's bytes.
struct FileLeaf {
    sha256: [u8; 32],
    size: u64,
}

/// The CID bytes and Tsize of the balanced file root of `content`, a file
/// over one leaf (trickle off). The bytes are split into [`CHUNK_SIZE`]-byte
/// raw leaves, the last one shorter, and the tree is
/// [`file_root_leaves`]`'s.
fn file_root(content: &[u8]) -> (Vec<u8>, u64) {
    let leaves: Vec<FileLeaf> = content
        .chunks(CHUNK_SIZE)
        .map(|chunk| FileLeaf {
            sha256: naming_hash(chunk),
            size: chunk.len() as u64,
        })
        .collect();
    file_root_leaves(&leaves)
}

/// The CID bytes and Tsize of the balanced file root over `leaves`, a file's
/// raw leaves in byte order (trickle off), at any depth. One leaf is that
/// leaf. More are grouped left to right: the nodes, left to right, in groups
/// of [`MAX_FILE_LINKS`], each group one dag-pb node, so only a level's last
/// node can be short, and a last group of one node is still a node of one
/// link. The pass that makes one node made the root. A node's links have
/// empty names, each child's CID and Tsize; its data has the bytes under it
/// as filesize and each child's filesize as one blocksize; its Tsize is its
/// block's length plus its children's Tsizes.
fn file_root_leaves(leaves: &[FileLeaf]) -> (Vec<u8>, u64) {
    let mut level: Vec<FileTreeNode> = leaves
        .iter()
        .map(|leaf| {
            let (cid, tsize) = raw_leaf(&leaf.sha256, leaf.size);
            FileTreeNode {
                cid,
                tsize,
                filesize: tsize,
            }
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(MAX_FILE_LINKS)
            .map(|children| {
                let links: Vec<Link<'_>> = children
                    .iter()
                    .map(|child| Link {
                        name: Cow::Borrowed(""),
                        cid: child.cid.clone(),
                        tsize: child.tsize,
                    })
                    .collect();
                let blocksizes: Vec<u64> = children.iter().map(|child| child.filesize).collect();
                let filesize = children.iter().map(|child| child.filesize).sum();
                let block = file_root_block(&links, &blocksizes, filesize);
                let tsize = dag_pb_tsize(&block, children.iter().map(|child| child.tsize));
                FileTreeNode {
                    cid: cid_bytes(DAG_PB_CODEC, &naming_hash(&block)),
                    tsize,
                    filesize,
                }
            })
            .collect();
    }
    let root = level.pop().expect("a file over one leaf has a root");
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
    /// on the way. A path with an empty, `.` or `..` part is refused; then a
    /// path with any other part that starts with `.`, which Kubo without
    /// `--hidden` leaves out of the CID; so is a path already given, and a
    /// path that is a file and a directory, in either order. Every naming
    /// call reaches this one path check.
    fn insert(&mut self, path: &str, file: Child) -> Result<(), Refusal> {
        let parts: Vec<&str> = path.split('/').collect();
        if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
            return Err(Refusal::BadPathPart {
                path: path.to_owned(),
            });
        }
        if parts.iter().any(|part| part.starts_with('.')) {
            return Err(Refusal::HiddenName {
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
                    directory.children.push((owned_path_part(part), made));
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
                directory.children.push((owned_path_part(name), file));
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

/// Store one path part as the UTF-8 bytes the walk gives it, so a name that
/// holds a combining mark keeps that mark: U+0301 stays in the name, and the
/// links estimate and the HAMT bucket hash read the same bytes. No
/// normalization runs, so two names that a normalizer would fold stay two
/// names.
fn owned_path_part(part: &str) -> String {
    part.to_owned()
}

/// One link of a directory block or a file root: the child's name (empty
/// under a file root), CID bytes and Tsize. A HAMT leaf link's name also
/// carries its bucket's two uppercase hex digits, and a link to a child
/// shard is named only those two digits.
struct Link<'a> {
    name: Cow<'a, str>,
    cid: Vec<u8>,
    tsize: u64,
}

/// One level of a HAMT: its links in bucket order and the bitmap of the
/// buckets it holds.
struct Shard<'a> {
    links: Vec<Link<'a>>,
    bitmap: [u8; HAMT_BITMAP_BYTES],
}

/// The sha2-256 digest and the Tsize of `directory`'s block, at the bundle
/// path `path` (empty for the root). Each child directory is encoded first,
/// and its link's Tsize is its block's length plus its links' Tsizes. The
/// links are sorted by name bytes. A directory is a basic directory when the
/// sum over its direct children of each name's byte length and
/// [`CIDV1_SHA256_LENGTH`] is at most [`DIRECTORY_LINKS_LIMIT`], whatever the
/// block's length; a greater estimate is a HAMT shard ([`encode_hamt`]).
/// `sha256` is the one naming hash.
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
        links.push(Link {
            name: Cow::Borrowed(name),
            cid,
            tsize,
        });
    }
    links.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let estimate: usize = links
        .iter()
        .map(|link| link.name.len() + CIDV1_SHA256_LENGTH)
        .sum();
    if estimate > DIRECTORY_LINKS_LIMIT {
        return encode_hamt(&links, path, sha256);
    }
    let block = directory_block(&links);
    let tsize = dag_pb_tsize(&block, links.iter().map(|link| link.tsize));
    Ok((sha256(&block), tsize))
}

/// The first 64 bits of murmur3 x64-128 with seed 0, big-endian: the digest
/// spaolacci's `New64` gives and its `Sum(nil)` writes. It is the marked lab
/// copy of Kubo's HAMT bucket hash and hashes a child's name, never its path.
fn hamt_digest(bytes: &[u8]) -> [u8; HAMT_DIGEST_BYTES] {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;
    let mut h1 = 0u64;
    let mut h2 = 0u64;
    let mut blocks = bytes.chunks_exact(16);
    for block in &mut blocks {
        let mut k1 = u64::from_le_bytes(block[0..8].try_into().expect("8 bytes"));
        let mut k2 = u64::from_le_bytes(block[8..16].try_into().expect("8 bytes"));
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
    let tail = blocks.remainder();
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    for (at, byte) in tail.iter().enumerate() {
        if at < 8 {
            k1 |= u64::from(*byte) << (8 * at);
        } else {
            k2 |= u64::from(*byte) << (8 * (at - 8));
        }
    }
    if tail.len() > 8 {
        h2 ^= k2.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
    }
    if !tail.is_empty() {
        h1 ^= k1.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    }
    h1 ^= bytes.len() as u64;
    h2 ^= bytes.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1.wrapping_add(h2).to_be_bytes()
}

/// The murmur3 final mix of one 64-bit word.
fn fmix64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^= value >> 33;
    value
}

/// The sha2-256 digest and Tsize of the HAMT shard of `links`, whose links
/// estimate is over [`DIRECTORY_LINKS_LIMIT`], at the bundle path `path`.
/// Each child's name is hashed once with [`hamt_digest`]; [`hamt_shard`]
/// takes one digest byte per level. `sha256` hashes every shard block.
fn encode_hamt(
    links: &[Link<'_>],
    path: &str,
    sha256: &dyn Fn(&[u8]) -> [u8; 32],
) -> Result<([u8; 32], u64), Refusal> {
    let digests: Vec<[u8; HAMT_DIGEST_BYTES]> = links
        .iter()
        .map(|link| hamt_digest(link.name.as_bytes()))
        .collect();
    let indices: Vec<usize> = (0..links.len()).collect();
    let shard = hamt_shard(links, &indices, &digests, 0, path, sha256)?;
    let block = hamt_block(&shard.links, &shard.bitmap);
    let tsize = dag_pb_tsize(&block, shard.links.iter().map(|link| link.tsize));
    Ok((sha256(&block), tsize))
}

/// One level of a HAMT over `indices`, the chosen positions in `links`, with
/// their `digests`, at `depth`, the digest byte this level takes. Buckets go
/// out in byte order. A bucket of one child is one leaf link named its two
/// uppercase hex digits and the child's name; a bucket of two or more is one
/// link named only the digits, pointing at the child shard from the next
/// digest byte. A shard of one link is allowed when the children share this
/// byte: only a bucket of one child is a leaf. A ninth byte is
/// [`Refusal::HamtTooDeep`].
fn hamt_shard<'a>(
    links: &[Link<'a>],
    indices: &[usize],
    digests: &[[u8; HAMT_DIGEST_BYTES]],
    depth: usize,
    path: &str,
    sha256: &dyn Fn(&[u8]) -> [u8; 32],
) -> Result<Shard<'a>, Refusal> {
    if depth == HAMT_DIGEST_BYTES {
        return Err(Refusal::HamtTooDeep { path: shown(path) });
    }
    let mut buckets: Vec<(u8, Vec<usize>)> = Vec::new();
    for &at in indices {
        let bucket = digests[at][depth];
        match buckets.iter_mut().find(|(seen, _)| *seen == bucket) {
            Some((_, bucket_indices)) => bucket_indices.push(at),
            None => buckets.push((bucket, vec![at])),
        }
    }
    buckets.sort_by_key(|(bucket, _)| *bucket);
    let mut shard = Shard {
        links: Vec::new(),
        bitmap: [0; HAMT_BITMAP_BYTES],
    };
    for (bucket, bucket_indices) in buckets {
        shard.bitmap[HAMT_BITMAP_BYTES - 1 - bucket as usize / 8] |= 1 << (bucket % 8);
        if bucket_indices.len() == 1 {
            let link = &links[bucket_indices[0]];
            shard.links.push(Link {
                name: Cow::Owned(format!("{bucket:02X}{}", link.name)),
                cid: link.cid.clone(),
                tsize: link.tsize,
            });
        } else {
            let child = hamt_shard(links, &bucket_indices, digests, depth + 1, path, sha256)?;
            let block = hamt_block(&child.links, &child.bitmap);
            let tsize = dag_pb_tsize(&block, child.links.iter().map(|link| link.tsize));
            shard.links.push(Link {
                name: Cow::Owned(format!("{bucket:02X}")),
                cid: cid_bytes(DAG_PB_CODEC, &sha256(&block)),
                tsize,
            });
        }
    }
    Ok(shard)
}

/// The UnixFS data of a HAMT shard with `bitmap`: type 5 (`08 05`), field 2
/// the bitmap's bytes after its leading zero bytes, `28 22` (hash type) and
/// `30 80 02` (fanout 256). The bitmap sets bucket `i` in byte `31 - i / 8`
/// at `1 << (i % 8)`, so bucket 0 is the last byte's low bit.
fn hamt_data(bitmap: &[u8; HAMT_BITMAP_BYTES]) -> Vec<u8> {
    let first = bitmap
        .iter()
        .position(|byte| *byte != 0)
        .expect("a shard holds at least one bucket");
    let mut data = vec![1 << 3, HAMT_SHARD_TYPE];
    put_length_delimited(&mut data, 2, &bitmap[first..]);
    data.push(5 << 3);
    put_varint(&mut data, HAMT_HASH_TYPE);
    data.push(6 << 3);
    put_varint(&mut data, u64::from(HAMT_FANOUT));
    data
}

/// A HAMT shard's dag-pb block: its links (`put_links`, in bucket order),
/// then the UnixFS data of [`hamt_data`] as field 1.
fn hamt_block(links: &[Link<'_>], bitmap: &[u8; HAMT_BITMAP_BYTES]) -> Vec<u8> {
    let mut block = Vec::new();
    put_links(&mut block, links);
    put_length_delimited(&mut block, 1, &hamt_data(bitmap));
    block
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

/// The dag-pb block of one node of a file's tree, the root or one below it:
/// its children as links (`put_links`, each name empty), then the UnixFS
/// data as field 1: its type `08 02`, a file, the `length` of the bytes under
/// it as filesize (field 3, `0x18`), and each child's filesize, from
/// `blocksizes`, as one blocksize (field 4, `0x20`, one tag per value, not
/// packed). A blocksize is never a child's Tsize. The data has no Data field
/// (field 2): the bytes are in the leaves.
fn file_root_block(children: &[Link<'_>], blocksizes: &[u64], length: u64) -> Vec<u8> {
    let mut block = Vec::new();
    put_links(&mut block, children);
    let mut data = vec![1 << 3, FILE_TYPE];
    data.push(3 << 3);
    put_varint(&mut data, length);
    for blocksize in blocksizes {
        data.push(4 << 3);
        put_varint(&mut data, *blocksize);
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

/// The Tsize of a dag-pb node: its block's length plus its children's
/// Tsizes. A basic directory, a HAMT shard, a child shard and every file
/// node take their Tsize here, so one sum names them all.
fn dag_pb_tsize(block: &[u8], child_tsizes: impl IntoIterator<Item = u64>) -> u64 {
    let block_len = block.len() as u64;
    let children = child_tsizes.into_iter().sum::<u64>();
    block_len + children
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

/// A folder the walk is in: its checked handle, the rest of its listing, its
/// bundle path (empty for the root) and how many files the walk had read
/// when it opened the folder.
struct Folder {
    handle: OwnedFd,
    listing: std::vec::IntoIter<Listed>,
    path: String,
    first_entry: usize,
}

/// Every regular file under `bundle`, each with its bundle-relative path.
///
/// The walk opens `bundle` once, as a folder. After that it reaches each
/// entry through its folder's handle: it checks the listed type, opens the
/// entry, checks the open handle, and only then reads or lists that handle.
/// It goes depth first, so it holds one handle per folder level. When a
/// folder below the root is done and the walk read no file since it opened
/// that folder, the folder holds no file at any depth and is refused. The
/// first refusal stops the walk. Listing order does not matter: the encoder
/// sorts.
fn collect_entries(
    bundle: &Path,
    observe: &mut dyn FnMut(Moment, &str),
) -> Result<Vec<BundleEntry>, Refusal> {
    let root = open_checked(CWD, bundle, EntryKind::Directory, "")?;
    let listing = list_folder(root.as_fd(), "")?;
    let mut folders = vec![Folder {
        handle: root,
        listing,
        path: String::new(),
        first_entry: 0,
    }];
    let mut entries = Vec::new();
    while let Some(folder) = folders.last_mut() {
        let Some(Listed {
            name,
            path,
            file_type,
        }) = folder.listing.next()
        else {
            let done = folders.pop().expect("the loop holds a folder");
            if !done.path.is_empty() && entries.len() == done.first_entry {
                return Err(Refusal::EmptyFolder { path: done.path });
            }
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
            folders.push(Folder {
                handle,
                listing,
                path,
                first_entry: entries.len(),
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamt_digest_is_the_marked_murmur3_copy() {
        // spaolacci's murmur3 x64-128 `New64` with seed 0 prints `hello`'s
        // first 64 bits big-endian as these eight bytes; the first bucket is
        // 0xCB, the first byte, not the last.
        assert_eq!(
            hamt_digest(b"hello"),
            [0xcb, 0xd8, 0xa7, 0xb3, 0x41, 0xbd, 0x9b, 0x02]
        );
        assert_eq!(hamt_digest(b""), [0; HAMT_DIGEST_BYTES]);
    }

    #[test]
    fn fifteen_byte_name_mixes_the_last_tail_byte() {
        // Task 065: `photo-tail.jpeg` is 15 bytes, so its murmur3 tail holds
        // tail indexes 0 to 14 and its last byte `g` is tail index 14, mixed
        // into the hash's second word. README's `murmur64` prints these eight
        // big-endian bytes for that name.
        let name = "photo-tail.jpeg";
        assert_eq!(name.len(), 15, "the name's bytes");
        assert_eq!(name.as_bytes().last(), Some(&b'g'), "the last byte");
        assert_eq!(
            hamt_digest(name.as_bytes()),
            [0x19, 0x64, 0x8b, 0xa3, 0x83, 0x36, 0xe8, 0xe4]
        );
    }

    #[test]
    fn sixteen_byte_name_mixes_its_last_block_once() {
        // Task 066: `photo-block.jpeg` is 16 bytes, one whole murmur3 block,
        // so its tail is empty and that block is mixed once. A tail that took
        // the last 16 bytes again would mix the same block twice and print
        // another name. README's `murmur64` prints these eight big-endian
        // bytes for that name.
        let name = "photo-block.jpeg";
        assert_eq!(name.len(), 16, "the name's bytes");
        assert_eq!(name.len() % 16, 0, "one whole block");
        assert_eq!(
            hamt_digest(name.as_bytes()),
            [0xfe, 0x17, 0x69, 0x64, 0xde, 0x66, 0x1a, 0x32]
        );
    }

    #[test]
    fn nine_byte_name_mixes_the_second_words_first_byte() {
        // Task 067: `photo.jpg` is 9 bytes, so its murmur3 tail is 9 bytes and
        // tail index 8, the first byte of the hash's second word, enters that
        // word. A tail of 8 never reaches it. README's `murmur64` prints
        // these eight big-endian bytes for that name.
        let name = "photo.jpg";
        assert_eq!(name.len(), 9, "the name's bytes");
        assert_eq!(name.as_bytes().last(), Some(&b'g'), "the last byte");
        assert_eq!(name.len() % 16, 9, "the tail's bytes");
        assert_eq!(
            hamt_digest(name.as_bytes()),
            [0xc8, 0x93, 0x6b, 0xcd, 0xf7, 0x98, 0x4c, 0x4c]
        );
    }

    #[test]
    fn hamt_data_trims_leading_zero_bitmap_bytes() {
        // Bucket 0 is the last byte's low bit, so its bitmap is one byte.
        let mut low = [0u8; HAMT_BITMAP_BYTES];
        low[HAMT_BITMAP_BYTES - 1] = 1;
        assert_eq!(
            hamt_data(&low),
            [0x08, 0x05, 0x12, 0x01, 0x01, 0x28, 0x22, 0x30, 0x80, 0x02]
        );
        // Bucket 255 is the first byte's high bit, so all 32 bytes stay.
        let mut high = [0u8; HAMT_BITMAP_BYTES];
        high[0] = 0x80;
        let data = hamt_data(&high);
        assert_eq!(&data[..4], &[0x08, 0x05, 0x12, 0x20]);
        assert_eq!(data[4], 0x80);
    }

    #[test]
    fn two_names_in_one_bucket_get_a_child_shard() {
        // Task 061: two 200-byte names whose digest bytes 0 and 1 are both
        // `FE 57` and whose byte 2 differs (`79` and `37`). The same pair
        // replaces two fillers in
        // `directory_with_a_one_link_hamt_shard_bundle`, where no other name
        // has digest byte 0 `FE`. Sharing two bytes makes the child shard
        // hold one link, but a bucket of two or more children is still one
        // link named only the first byte's two uppercase hex digits,
        // pointing at that child shard: the collision level is necessary
        // even when the child shard holds one link.
        let names = [format!("one-{:0>196}", 62), format!("two-{:0>196}", 35_399)];
        for name in &names {
            assert_eq!(name.len(), 200, "a bundle name fits in a folder");
        }
        let digests: Vec<[u8; HAMT_DIGEST_BYTES]> = names
            .iter()
            .map(|name| hamt_digest(name.as_bytes()))
            .collect();
        assert_eq!(
            digests[0][..2],
            digests[1][..2],
            "the two names share digest bytes 0 and 1"
        );
        assert_eq!(digests[0][..2], [0xFE, 0x57], "the shared two-byte prefix");
        assert_ne!(
            digests[0][2], digests[1][2],
            "the two names differ at digest byte 2"
        );
        let links = [
            Link {
                name: Cow::Owned(names[0].clone()),
                cid: vec![0x01, 0xaa],
                tsize: 1,
            },
            Link {
                name: Cow::Owned(names[1].clone()),
                cid: vec![0x01, 0xbb],
                tsize: 2,
            },
        ];
        let shard = hamt_shard(&links, &[0, 1], &digests, 0, "", &naming_hash)
            .expect("two names sharing two bytes are a shard");
        let bucket = digests[0][0];
        assert_eq!(shard.links.len(), 1, "one bucket is one link");
        assert_eq!(
            shard.links[0].name,
            format!("{bucket:02X}"),
            "a bucket of two children is named only its first digest byte"
        );
        assert!(
            !shard.links[0].name.contains(names[0].as_str())
                && !shard.links[0].name.contains(names[1].as_str()),
            "a shard link name holds no child's leaf name"
        );
        assert_eq!(
            shard.bitmap[HAMT_BITMAP_BYTES - 1 - bucket as usize / 8],
            1 << (bucket % 8),
            "the bitmap sets the bucket's own bit"
        );
        assert_eq!(
            shard.bitmap.iter().filter(|byte| **byte != 0).count(),
            1,
            "only one bucket is set"
        );
        assert_ne!(shard.links[0].cid, vec![0x01, 0xaa]);
        assert_ne!(shard.links[0].cid, vec![0x01, 0xbb]);
    }
}
