//! Lab capsule identity: one deterministic **lab CID** over a whole capsule
//! bundle (PRINCIPLES 13 and 15).
//!
//! This crate answers one question: "do these bytes match this name?". It
//! never answers "may this run?": it makes no trust, admission or launch
//! decision and sits in no admission or launch path. Its value is a lab CID,
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
//! [`lab_cid`] walks a bundle and hands its entries to [`encode_entries`],
//! the encoder. Together they are the only code that names a bundle; tests
//! and tools call them and re-implement neither. The walk's two checks,
//! [`entry_kind`] and [`entry_path`], are public only so tests can give them
//! what a test folder cannot hold: a device, or a name that is not UTF-8.
#![forbid(unsafe_code)]

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use elastos_common::CapsuleManifest;
use sha2::{Digest, Sha256};

/// The first bytes of every lab CID stream.
pub const FRAMING_TAG: &[u8] = b"lab.capsule-identity.bundle/v1\n";

/// How a lab CID prints before its 64 lowercase hex characters.
pub const LAB_CID_PREFIX: &str = "lab-cid:sha256:";

/// The manifest every bundle holds at its root.
pub const MANIFEST_FILE: &str = "capsule.json";

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

/// One regular file of a bundle: its bundle-relative, `/`-separated path and
/// its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleEntry {
    pub path: String,
    pub content: Vec<u8>,
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

/// Why a bundle gets no lab CID. Each refusal has its own reason, and a
/// refused bundle gets no name.
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
    /// The walk could not read an entry; `.` is the bundle root.
    Unreadable { path: String, error: String },
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
            Refusal::Unreadable { path, error } => write!(f, "could not read {path}: {error}"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Name the bundle at `bundle` by its lab CID.
///
/// The walk checks each entry's own type before it opens it (it never
/// follows a link) and reads every regular file once. Then the root
/// `capsule.json` it read gets the Runtime's own two checks, and exactly the
/// bytes that were checked are named. A refusal returns no name.
pub fn lab_cid(bundle: &Path) -> Result<LabCid, Refusal> {
    let entries = collect_entries(bundle)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or(Refusal::NoManifest)?;
    check_manifest(&manifest.content)?;
    encode_entries(&entries)
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

/// The kind of one entry, from its own type as `fs::symlink_metadata`
/// reports it. Only a directory or a regular file may be in a bundle;
/// everything else is [`EntryKind::Special`].
pub fn entry_kind(file_type: fs::FileType) -> EntryKind {
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

/// Every regular file under `root`, each with its bundle-relative path. Each
/// entry's own type is checked before the entry is opened, and the first
/// refusal stops the walk. Listing order does not matter: the encoder sorts.
fn collect_entries(root: &Path) -> Result<Vec<BundleEntry>, Refusal> {
    let mut entries = Vec::new();
    let mut folders = vec![(root.to_path_buf(), String::new())];
    while let Some((folder, prefix)) = folders.pop() {
        let listing = fs::read_dir(&folder).map_err(|error| unreadable(&prefix, error))?;
        for item in listing {
            let item = item.map_err(|error| unreadable(&prefix, error))?;
            let path = entry_path(&prefix, &item.file_name())?;
            let on_disk = item.path();
            let file_type = fs::symlink_metadata(&on_disk)
                .map_err(|error| unreadable(&path, error))?
                .file_type();
            match entry_kind(file_type) {
                EntryKind::Directory => folders.push((on_disk, path)),
                EntryKind::RegularFile => {
                    let content = fs::read(&on_disk).map_err(|error| unreadable(&path, error))?;
                    entries.push(BundleEntry { path, content });
                }
                EntryKind::Special(kind) => return Err(Refusal::NotRegularFile { path, kind }),
            }
        }
    }
    Ok(entries)
}

/// The Runtime's own two checks on `capsule.json`, the same two calls it
/// makes on a fetched bundle's manifest: parse it as `CapsuleManifest`
/// (which refuses an unknown field), then `validate()`. The lab adds no rule.
fn check_manifest(bytes: &[u8]) -> Result<(), Refusal> {
    let manifest: CapsuleManifest = serde_json::from_slice(bytes)
        .map_err(|error| Refusal::ManifestUnparsed(error.to_string()))?;
    manifest.validate().map_err(Refusal::ManifestInvalid)
}

fn special_name(file_type: fs::FileType) -> &'static str {
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

fn unreadable(path: &str, error: io::Error) -> Refusal {
    let path = if path.is_empty() { "." } else { path };
    Refusal::Unreadable {
        path: path.to_owned(),
        error: error.to_string(),
    }
}
