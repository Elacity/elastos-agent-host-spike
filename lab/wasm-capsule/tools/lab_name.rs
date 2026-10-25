//! The one rule that names a wc-003 lab bundle: which files the closure holds,
//! the exact bytes that are hashed, and the label on the result.
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

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    let files = read_bundle(dir)?;
    lab_name(&files).map_err(|reason| Refusal::new(dir, reason))
}

/// Read `dir` as a lab closure and fail closed on anything else: an entry that
/// is not one of [`CLOSURE_PATHS`], a closure entry that is not a regular file
/// (a symlink is never followed), and a closure file that is missing. The files
/// come back in directory listing order; [`canonical_closure`] sorts them.
pub fn read_bundle(dir: &Path) -> Result<Vec<ClosureFile>, Refusal> {
    let entries = fs::read_dir(dir)
        .map_err(|err| Refusal::new(dir, format!("cannot be read as a bundle ({err})")))?;
    let mut files = Vec::new();
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
        let meta = fs::symlink_metadata(&path)
            .map_err(|err| Refusal::new(&path, format!("cannot be inspected ({err})")))?;
        if !meta.file_type().is_file() {
            return Err(Refusal::new(
                &path,
                "is not a regular file (a symlink, directory or device is never part of the lab closure)",
            ));
        }
        let bytes = fs::read(&path)
            .map_err(|err| Refusal::new(&path, format!("cannot be read ({err})")))?;
        files.push(ClosureFile {
            path: name.to_string(),
            bytes,
        });
    }
    for required in CLOSURE_PATHS {
        if !files.iter().any(|file| file.path == required) {
            return Err(Refusal::new(
                &dir.join(required),
                "is missing from the lab closure",
            ));
        }
    }
    Ok(files)
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
