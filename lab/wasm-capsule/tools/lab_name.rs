//! The one rule that names a wc-003 lab bundle: which files the closure holds,
//! the exact bytes that are hashed, and the label on the result. It also holds
//! the one check every capsule file read or write of the `bundle` tool goes
//! through ([`open_regular`]), so it never reads or writes through a link.
//!
//! The `bundle` tool (tools/bundle.rs) and the named tests (tests/bundle.rs)
//! compile this same file, so naming a bundle has one path (PRINCIPLES P10).
//!
//! The result is a LAB name, `lab-sha256:<hex>`. It is not a CID. The Runtime
//! names an artifact by the CIDv1 dag-pb root that its IPFS provider gets from
//! Kubo under a pinned UnixFS import profile (ADOPTION.md has the discovery),
//! and this rule does not reproduce that. So the lab name must never be shown
//! as a CID, and it is never a package identity (P13): no Runtime admission or
//! launch path reads it.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The open(2) flags and the errno [`open_regular`] needs, from macOS
/// <sys/fcntl.h> and <sys/errno.h>. The lane has no dependencies (so no `libc`
/// crate) and is built and tested on this one Mac, so any other OS is a compile
/// error, never a guessed value.
#[cfg(target_os = "macos")]
mod sys {
    pub const O_NONBLOCK: i32 = 0x0004;
    pub const O_NOFOLLOW: i32 = 0x0100;
    pub const ELOOP: i32 = 62;
}

#[cfg(not(target_os = "macos"))]
compile_error!(
    "the lab's no-follow open knows only the macOS flag values: add this OS's \
     O_NOFOLLOW, O_NONBLOCK and ELOOP from its headers, then run the symlink and \
     FIFO tests in tests/bundle.rs"
);

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

/// Read and name a bundle directory. Both modes of the `bundle` tool name a
/// bundle through this one function.
pub fn name_bundle(dir: &Path) -> Result<String, Refusal> {
    let files = read_bundle(dir, &mut no_seam)?;
    lab_name(&files).map_err(|reason| Refusal::new(dir, reason))
}

/// A moment in [`read_file`] at which a test may change the bundle, to prove
/// that the change cannot reach the name. The lab tools pass [`no_seam`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Moment {
    /// The path is known (the listing named it), and it is not opened yet.
    BeforeOpen,
    /// The file is open and its handle checked, and it is not read yet.
    BeforeRead,
}

/// The seam the lab tools pass: it changes nothing.
pub fn no_seam(_: Moment, _: &Path) {}

/// Read `dir` as a lab closure and fail closed on anything else: an entry that
/// is not one of [`CLOSURE_PATHS`], a closure file that is missing, and a
/// closure file [`read_file`] refuses (a symlink, or anything but a regular
/// file). The listing decides the closure before any file is opened. The files
/// come back in listing order; [`canonical_closure`] sorts them.
pub fn read_bundle(
    dir: &Path,
    seam: &mut dyn FnMut(Moment, &Path),
) -> Result<Vec<ClosureFile>, Refusal> {
    let entries = fs::read_dir(dir)
        .map_err(|err| Refusal::new(dir, format!("cannot be read as a bundle ({err})")))?;
    let mut listed = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| Refusal::new(dir, format!("cannot be listed ({err})")))?;
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

/// Read one file: open it with [`open_regular`], which checks the handle, and
/// read that same handle. The path is looked up once, by the open, so a link
/// put at the path at any moment never brings outside bytes into a name:
/// before the open, the open refuses it; after it, nothing looks at the path.
pub fn read_file(path: &Path, seam: &mut dyn FnMut(Moment, &Path)) -> Result<Vec<u8>, Refusal> {
    seam(Moment::BeforeOpen, path);
    let mut file = open_regular(path, OpenOptions::new().read(true))?;
    seam(Moment::BeforeRead, path);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| Refusal::new(path, format!("cannot be read ({err})")))?;
    Ok(bytes)
}

/// The one check for every capsule file the `bundle` tool reads or writes (and
/// every closure file the tests read). It opens `path` with `options` plus
/// O_NOFOLLOW, so the open itself refuses a link and no moment passes between a
/// check and the open, and O_NONBLOCK, so it never waits on a FIFO or a device.
/// Then it checks the handle it opened, never the path again: only a regular
/// file is accepted. The caller reads or writes the returned handle, so the
/// file that was checked is the file that is used.
pub fn open_regular(path: &Path, options: &mut OpenOptions) -> Result<File, Refusal> {
    let file = options
        .custom_flags(sys::O_NOFOLLOW | sys::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(sys::ELOOP) {
                Refusal::new(
                    path,
                    "is a symlink (a symlink is never followed, to read or to write)",
                )
            } else {
                Refusal::new(path, format!("cannot be opened ({err})"))
            }
        })?;
    let meta = file
        .metadata()
        .map_err(|err| Refusal::new(path, format!("cannot be inspected ({err})")))?;
    if !meta.file_type().is_file() {
        return Err(Refusal::new(
            path,
            "is not a regular file (a directory, FIFO or device is never part of the lab closure)",
        ));
    }
    Ok(file)
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

/// The lab name of a closure: [`LAB_NAME_PREFIX`] and the lowercase hex sha256
/// of its [`canonical_closure`].
pub fn lab_name(files: &[ClosureFile]) -> Result<String, String> {
    let digest = sha256_hex(&canonical_closure(files))?;
    Ok(format!("{LAB_NAME_PREFIX}{digest}"))
}

/// The lowercase hex sha256 of `bytes`, from the system tool (`sha256sum`, else
/// `shasum -a 256`), the same tools tools/build hashes with. No Rust crate, so
/// the lane stays free of dependencies. Anything but 64 hex digits fails closed.
fn sha256_hex(bytes: &[u8]) -> Result<String, String> {
    for (bin, args) in [("sha256sum", &[][..]), ("shasum", &["-a", "256"][..])] {
        let Ok(mut child) = Command::new(bin)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        else {
            continue;
        };
        // The digest is printed only after end of input, so writing all of it
        // first cannot fill the output pipe. Dropping stdin sends that end.
        let written = child
            .stdin
            .take()
            .expect("the hash tool's stdin is piped")
            .write_all(bytes);
        let output = child
            .wait_with_output()
            .map_err(|err| format!("{bin} did not finish ({err})"))?;
        if written.is_err() || !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let digest = text.split_whitespace().next().unwrap_or("");
        if digest.len() == 64
            && digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Ok(digest.to_string());
        }
        return Err(format!("{bin} printed no sha256 digest"));
    }
    Err("no sha256 tool (sha256sum or shasum) is available".to_string())
}
