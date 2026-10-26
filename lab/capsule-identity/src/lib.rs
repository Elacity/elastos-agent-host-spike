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

use elastos_common::CapsuleManifest;
use rustix::fs::{fstat, openat, Dir, FileType, Mode, OFlags, CWD};
use rustix::io::Errno;
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

/// A bundle as the one walk checked it: its lab CID and every regular file
/// the walk read, each with the bytes read from its checked handle.
///
/// Only [`checked_bundle`] and [`checked_bundle_observed`] make one, from the
/// one walk and the one manifest check. Its fields are private and nothing
/// changes them, so its lab CID always names its entries. It holds a name and
/// bytes, never a decision: it is no trust, admission or launch value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedBundle {
    cid: LabCid,
    entries: Vec<BundleEntry>,
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

/// Why a bundle gets no lab CID, or why a name check ([`check_name`] or
/// [`CheckedBundle::check_name`]) refuses a claimed name. Each refusal has
/// its own reason, and a refused bundle gets no name.
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
    /// A name check was given a claim that is not a lab CID: it lacks the
    /// `lab-cid:sha256:` label, or 64 lowercase hex characters after it. The
    /// claim is kept only to say what was refused.
    NotALabCid { claimed: String },
    /// A name check was given a lab CID the bundle's bytes do not give.
    /// `actual` is the lab CID of the bytes; the claim is kept only to say
    /// what was refused.
    NameMismatch { actual: LabCid, claimed: String },
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
/// checks, and exactly the bytes that were checked are named and kept. This
/// is the one walk and the one manifest check. A refusal returns no value.
pub fn checked_bundle_observed(
    bundle: &Path,
    mut observe: impl FnMut(Moment, &str),
) -> Result<CheckedBundle, Refusal> {
    let entries = collect_entries(bundle, &mut observe)?;
    let manifest = entries
        .iter()
        .find(|entry| entry.path == MANIFEST_FILE)
        .ok_or(Refusal::NoManifest)?;
    check_manifest(&manifest.content)?;
    encode_entries(&entries)
        // The value keeps the very entries its lab CID names: no second read.
        .map(|cid| CheckedBundle { cid, entries })
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
fn check_manifest(bytes: &[u8]) -> Result<(), Refusal> {
    let manifest: CapsuleManifest = serde_json::from_slice(bytes)
        .map_err(|error| Refusal::ManifestUnparsed(error.to_string()))?;
    manifest.validate().map_err(Refusal::ManifestInvalid)
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
