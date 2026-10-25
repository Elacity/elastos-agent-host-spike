//! The one rule that names a wc-003 lab bundle: which files the closure holds,
//! the exact bytes that are hashed, and the label on the result. It also holds
//! the one read-only check every closure file is opened through
//! ([`open_regular`]), so a name never covers bytes reached through a link, and
//! naming never writes, truncates or creates a file.
//!
//! [`name_bundle`] is the one naming entry point. The named tests
//! (tests/lab_name.rs in the lab root) call this same module, so naming a
//! bundle has one path (PRINCIPLES P10). The hash is SHA-256 from the `sha2`
//! crate, computed in-process: naming starts no process and reads no PATH, so
//! once the bytes are read it cannot fail.
//!
//! The result is a LAB name, `lab-sha256:<hex>`. It is not a CID. The Runtime
//! names an artifact by the CIDv1 dag-pb root that its IPFS provider gets from
//! Kubo under a pinned UnixFS import profile (ADOPTION.md has the discovery),
//! and this rule does not reproduce that. So the lab name must never be shown
//! as a CID, and it is never a package identity (P13): no Runtime admission or
//! launch path reads it.

use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The label on every lab name. It says "lab", never "CID".
pub const LAB_NAME_PREFIX: &str = "lab-sha256:";

/// The first bytes of every canonical closure: the rule's name and version.
/// They separate the lab name from the plain sha256 of any one file (such as
/// the receipt's `artifact_sha256`) and from any other framing.
pub const CLOSURE_TAG: &[u8] = b"wc-003.lab-closure/v1\n";

/// The bundle's lab manifest.
pub const MANIFEST_PATH: &str = "capsule.json";

/// The bundle's one payload: the core Wasm module.
pub const MODULE_PATH: &str = "capsule.wasm";

/// The complete closure: exactly these paths, each a regular file.
pub const CLOSURE_PATHS: [&str; 2] = [MANIFEST_PATH, MODULE_PATH];

/// One file of the closure: its bundle-relative path and its exact bytes.
/// Nothing else about the file is kept (mtime, mode, owner, the order it was
/// written or listed in), so nothing else can reach the name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureFile {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Why a bundle cannot be named: the offending path and a plain reason, so a
/// refusal says what is wrong and where (P11).
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub path: PathBuf,
    pub reason: String,
}

impl Refusal {
    pub fn new(path: &Path, reason: impl Into<String>) -> Refusal {
        Refusal {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.reason)
    }
}

/// Read and name a bundle directory: [`read_bundle`], then [`lab_name`]. The
/// one naming entry point every lab tool calls.
pub fn name_bundle(dir: &Path) -> Result<String, Refusal> {
    let files = read_bundle(dir, &mut no_seam)?;
    Ok(lab_name(&files))
}

/// A moment in [`read_file`] at which a test may change the bundle, to prove
/// that the change cannot reach the name. [`name_bundle`] passes [`no_seam`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moment {
    /// The path is known (the listing named it), and it is not opened yet.
    BeforeOpen,
    /// The file is open and its handle checked, and it is not read yet.
    BeforeRead,
}

/// The seam [`name_bundle`] passes: it changes nothing.
pub fn no_seam(_: Moment, _: &Path) {}

/// Read `dir` as a lab closure and fail closed on anything else: a directory
/// that cannot be listed, an entry that is not one of [`CLOSURE_PATHS`], a
/// closure file that is missing, and a closure file [`read_file`] refuses. The
/// listing decides the closure before any file is opened. The files come back
/// in listing order; [`canonical_closure`] sorts them.
pub fn read_bundle(
    dir: &Path,
    seam: &mut dyn FnMut(Moment, &Path),
) -> Result<Vec<ClosureFile>, Refusal> {
    let entries = fs::read_dir(dir).map_err(|err| unlistable(dir, err))?;
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| unlistable(dir, err))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let Some(name) = file_name
            .to_str()
            .filter(|name| CLOSURE_PATHS.contains(name))
        else {
            return Err(Refusal::new(
                &path,
                "is not part of the lab closure (a lab bundle holds exactly capsule.json and capsule.wasm)",
            ));
        };
        listed.push((name.to_string(), path));
    }
    for required in CLOSURE_PATHS {
        if !listed.iter().any(|(name, _)| name == required) {
            return Err(Refusal::new(
                &dir.join(required),
                "is missing from the lab closure",
            ));
        }
    }
    let mut files = Vec::new();
    for (name, path) in listed {
        let bytes = read_file(&path, seam)?;
        files.push(ClosureFile { path: name, bytes });
    }
    Ok(files)
}

/// The refusal for a bundle directory whose listing fails, at its start or
/// part way through, with the cause the OS gave.
fn unlistable(dir: &Path, err: io::Error) -> Refusal {
    Refusal::new(dir, format!("cannot be listed as a lab bundle ({err})"))
}

/// Read one file: open it with [`open_regular`], which checks the handle, and
/// read that same handle with [`read_handle`]. The path is looked up once, by
/// the open, so a link put at the path at any moment never brings outside
/// bytes into a name: before the open, the open refuses it; after it, nothing
/// looks at the path.
pub fn read_file(path: &Path, seam: &mut dyn FnMut(Moment, &Path)) -> Result<Vec<u8>, Refusal> {
    seam(Moment::BeforeOpen, path);
    let file = open_regular(path)?;
    seam(Moment::BeforeRead, path);
    read_handle(path, &file)
}

/// Read every byte of `file`, the handle [`open_regular`] gave for `path`. A
/// read that fails is refused with the path and the cause the OS gave. It is
/// apart from [`read_file`] only so a test can hand it a handle whose read
/// fails: a regular file opened for reading cannot be made to fail on demand.
pub fn read_handle(path: &Path, mut file: &File) -> Result<Vec<u8>, Refusal> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| Refusal::new(path, format!("cannot be read ({err})")))?;
    Ok(bytes)
}

/// The one check every closure file is opened through. It builds its own
/// options and opens `path` for reading only, so no caller can make it write,
/// truncate or create a file. It adds `O_NOFOLLOW`, so the open itself refuses
/// a link and no moment passes between a check and the open, and `O_NONBLOCK`,
/// so it never waits on a FIFO or a device. Both flags come from `libc`, as in
/// the Runtime's own no-follow open
/// (`elastos/crates/elastos-runtime/src/provider/bridge.rs:118-124`). Then
/// [`check_regular`] checks the handle it opened, never the path again: only a
/// regular file is accepted. The caller reads the returned handle, so the file
/// that was checked is the file that is used.
pub fn open_regular(path: &Path) -> Result<File, Refusal> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                Refusal::new(path, "is a symlink (a symlink is never followed)")
            } else {
                Refusal::new(path, format!("cannot be opened ({err})"))
            }
        })?;
    check_regular(path, file.metadata())?;
    Ok(file)
}

/// Accept the handle [`open_regular`] opened for `path` only if `inspected`,
/// that handle's own inspection, says it is a regular file. An inspection that
/// failed is refused with the path and the cause the OS gave. It is apart from
/// [`open_regular`] only so a test can hand it an inspection that failed: the
/// inspection of an open handle cannot be made to fail on demand. Give it only
/// the inspection of an opened handle: a check of a path, then an open of that
/// path, is the race [`open_regular`] closes.
pub fn check_regular(path: &Path, inspected: io::Result<Metadata>) -> Result<(), Refusal> {
    let meta =
        inspected.map_err(|err| Refusal::new(path, format!("cannot be inspected ({err})")))?;
    if !meta.file_type().is_file() {
        return Err(Refusal::new(
            path,
            "is not a regular file (a directory, FIFO or device is never part of the lab closure)",
        ));
    }
    Ok(())
}

/// The exact bytes a lab name hashes: [`CLOSURE_TAG`], then each file in
/// ascending byte order of its path, as
/// `<path length> SP <path> SP <content length> SP <content>`, where a length
/// is the byte count in decimal ASCII with no leading zeros. Every field is
/// length-framed, so two different closures never give the same bytes. Only
/// paths and contents are read: no mtime, mode or owner.
pub fn canonical_closure(files: &[ClosureFile]) -> Vec<u8> {
    let mut sorted: Vec<&ClosureFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut closure = CLOSURE_TAG.to_vec();
    for file in sorted {
        closure.extend_from_slice(format!("{} {} ", file.path.len(), file.path).as_bytes());
        closure.extend_from_slice(format!("{} ", file.bytes.len()).as_bytes());
        closure.extend_from_slice(&file.bytes);
    }
    closure
}

/// The lab name of a closure: [`LAB_NAME_PREFIX`] and the lowercase hex
/// SHA-256 of its [`canonical_closure`], from `sha2`, in-process. It has no
/// failure path: it starts no process and reads no PATH.
pub fn lab_name(files: &[ClosureFile]) -> String {
    let digest = Sha256::digest(canonical_closure(files));
    format!("{LAB_NAME_PREFIX}{digest:x}")
}
