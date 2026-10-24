//! The closure listing: every file a capsule ships, as canonical JSON.
//!
//! `{"files":[{"path","sha256","size"}...],"schema":"elastos.capsule.closure/v1"}`,
//! files sorted by path bytes, keys sorted, no whitespace. The keys are ASCII
//! and no path may hold a control character, so this is also the RFC 8785
//! (JCS) form of the document.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};
use unicode_normalization::is_nfc;

use crate::{cid_v1_raw_sha256, io, Refusal};

pub const LISTING_SCHEMA: &str = "elastos.capsule.closure/v1";
/// JCS numbers are IEEE doubles; sizes must be exact integers there.
const MAX_EXACT_SIZE: u64 = (1 << 53) - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Lists every regular file under `root`. Symlinks and special files are
/// refused, never followed. Paths must be ASCII or NFC and unique under
/// case folding.
pub fn list_closure(root: &Path) -> Result<Vec<Entry>, Refusal> {
    Ok(read_closure(root)?.0)
}

/// The listing and the `capsule.json` bytes it lists, read in the same pass.
pub(crate) fn read_closure(root: &Path) -> Result<(Vec<Entry>, Vec<u8>), Refusal> {
    let (root, meta) = real_path(root)?;
    let root = root.as_path();
    if !meta.is_dir() {
        return Err(Refusal::SpecialFile(root.display().to_string()));
    }
    let dir = open_dir(root)?;
    let shown = root.display().to_string();
    let mut entries = Vec::new();
    let mut manifest = None;
    walk_regular_files(&dir, "", &shown, &mut |parent, name, relative, shown| {
        let mut file = open_regular_at(parent, name, shown)?;
        let meta = file.metadata().map_err(|err| io(err, Path::new(shown)))?;
        if meta.len() > MAX_EXACT_SIZE {
            return Err(Refusal::PathInvalid(format!(
                "{relative} is too large to list"
            )));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|err| io(err, Path::new(shown)))?;
        entries.push(Entry {
            path: relative.to_string(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
        if relative == "capsule.json" {
            manifest = Some(bytes);
        }
        Ok(())
    })?;
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    check_unique_under_case_folding(entries.iter().map(|entry| entry.path.as_str()))?;
    let manifest = manifest.ok_or(Refusal::ManifestMissing)?;
    Ok((entries, manifest))
}

/// `path` rebuilt from its parts, with every prefix that exists lstat'ed: no
/// part of it may be a symlink (the root itself, or a folder on the way to
/// it). The walk lstats everything below it, so nothing is read through a
/// link.
///
/// The path is rebuilt from `Path::components()` before any lstat, because on
/// POSIX lstat of `link/` or `link/.` follows the link: trailing `/` and `.`
/// parts go. A `..` part and an empty path are refused. A path through a
/// system link (macOS `/tmp` or `/var`) is refused too; give its real path.
///
/// Parts that do not exist yet are kept as written, so this is also how `pack`
/// checks the folder it is about to create: the caller decides whether the
/// whole path must exist.
pub(crate) fn check_prefixes(path: &Path) -> Result<PathBuf, Refusal> {
    if path.as_os_str().is_empty() {
        return Err(Refusal::PathInvalid("an empty path".to_string()));
    }
    // Below the first part that is not there, nothing is: the rest is kept,
    // never lstat'ed.
    let mut exists = true;
    let mut rebuilt = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Prefix(_) | Component::RootDir => rebuilt.push(part.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(Refusal::PathInvalid(format!(
                    "{} has a .. part",
                    path.display()
                )))
            }
            Component::Normal(name) => {
                rebuilt.push(name);
                if !exists {
                    continue;
                }
                match std::fs::symlink_metadata(&rebuilt) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        return Err(Refusal::SymlinkInPath(rebuilt.display().to_string()))
                    }
                    Ok(_) => {}
                    Err(_) => exists = false,
                }
            }
        }
    }
    if rebuilt.as_os_str().is_empty() {
        // Only `.` parts: the current folder, which lstat reports as itself.
        rebuilt.push(".");
    }
    Ok(rebuilt)
}

/// [`check_prefixes`] for a path that must exist: the rebuilt path and its
/// metadata.
pub(crate) fn real_path(path: &Path) -> Result<(PathBuf, std::fs::Metadata), Refusal> {
    let rebuilt = check_prefixes(path)?;
    let meta = std::fs::symlink_metadata(&rebuilt).map_err(|err| io(err, &rebuilt))?;
    Ok((rebuilt, meta))
}

/// Two paths that differ only by case would be one file on a
/// case-insensitive disk, so the listing would not describe what is there.
/// Full Unicode case folding: `ß` and `ss`, `ς` and `σ` collide too.
pub fn check_unique_under_case_folding<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> Result<(), Refusal> {
    let mut folded: BTreeMap<String, &str> = BTreeMap::new();
    for path in paths {
        if let Some(other) = folded.insert(caseless::default_case_fold_str(path), path) {
            return Err(Refusal::PathCaseCollision(
                other.to_string(),
                path.to_string(),
            ));
        }
    }
    Ok(())
}

/// `name` for an `openat` call; a name with a NUL byte is not a path we made.
pub(crate) fn c_name(name: &OsStr, shown: &str) -> Result<CString, Refusal> {
    CString::new(name.as_bytes()).map_err(|_| Refusal::PathInvalid(shown.to_string()))
}

/// Opens `name` below `dir` with `flags` and `O_NOFOLLOW`, so a link swapped in
/// after a check is refused by the open itself, not read through.
pub(crate) fn open_at(
    dir: &std::fs::File,
    name: &OsStr,
    flags: i32,
    shown: &str,
) -> Result<std::fs::File, Refusal> {
    let name = c_name(name, shown)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        let is_link = err.raw_os_error() == Some(libc::ELOOP)
            || (flags & libc::O_DIRECTORY != 0 && err.raw_os_error() == Some(libc::ENOTDIR));
        return Err(match is_link {
            true => Refusal::SymlinkInPath(shown.to_string()),
            false => io(err, Path::new(shown)),
        });
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Opens `path` itself and every folder on the way to it, one `openat` at a
/// time from the root (or the current folder), each with `O_NOFOLLOW`.
pub(crate) fn open_dir(path: &Path) -> Result<std::fs::File, Refusal> {
    let mut dir = if path.is_absolute() {
        std::fs::File::open("/").map_err(|err| io(err, Path::new("/")))?
    } else {
        std::fs::File::open(".").map_err(|err| io(err, Path::new(".")))?
    };
    let mut shown = if path.is_absolute() {
        "/".to_string()
    } else {
        ".".to_string()
    };
    for part in path.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        shown = format!("{shown}/{}", name.to_string_lossy());
        dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, &shown)?;
    }
    Ok(dir)
}

/// Opens `relative` below `root`: folders on the way with `O_DIRECTORY`, the
/// last part with `leaf_flags`. `create` makes missing folders below `root`.
pub(crate) fn open_in(
    root: &std::fs::File,
    relative: &str,
    leaf_flags: i32,
    create: bool,
    shown_root: &str,
) -> Result<std::fs::File, Refusal> {
    let mut dir = None;
    let mut shown = shown_root.trim_end_matches('/').to_string();
    let parts: Vec<&str> = relative.split('/').collect();
    for (index, name) in parts.iter().enumerate() {
        shown = format!("{shown}/{name}");
        let parent = dir.as_ref().unwrap_or(root);
        if index + 1 == parts.len() {
            return open_at(parent, OsStr::new(name), leaf_flags, &shown);
        }
        if create {
            let name_c = c_name(OsStr::new(name), &shown)?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o755) } < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EEXIST) {
                    return Err(io(err, Path::new(&shown)));
                }
            }
        }
        dir = Some(open_at(
            parent,
            OsStr::new(name),
            libc::O_RDONLY | libc::O_DIRECTORY,
            &shown,
        )?);
    }
    Err(Refusal::PathInvalid(relative.to_string()))
}

/// Opens one source file below `dir` and proves the opened handle is a regular
/// file. The open is non-blocking, so a FIFO swapped in between a walk's
/// `fstatat` and this open is refused instead of blocking; the `fstat` on the
/// handle, not a path lookup, decides. A folder or special file is refused
/// with nothing read.
pub(crate) fn open_regular_at(
    dir: &std::fs::File,
    name: &OsStr,
    shown: &str,
) -> Result<std::fs::File, Refusal> {
    let file = open_at(dir, name, libc::O_RDONLY | libc::O_NONBLOCK, shown)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } < 0 {
        return Err(io(std::io::Error::last_os_error(), Path::new(shown)));
    }
    if (stat.st_mode as u32) & (libc::S_IFMT as u32) != libc::S_IFREG as u32 {
        return Err(Refusal::SpecialFile(shown.to_string()));
    }
    Ok(file)
}

/// Opens one source file at `relative` below the opened folder `root`; folders
/// on the way with `O_DIRECTORY`, the file with [`open_regular_at`].
pub(crate) fn open_regular_in(
    root: &std::fs::File,
    relative: &str,
    shown_root: &str,
) -> Result<std::fs::File, Refusal> {
    let parts: Vec<&str> = relative.split('/').collect();
    let shown = format!("{shown_root}/{relative}");
    if parts.len() == 1 {
        return open_regular_at(root, OsStr::new(relative), &shown);
    }
    let folder = parts[..parts.len() - 1].join("/");
    let dir = open_in(
        root,
        &folder,
        libc::O_RDONLY | libc::O_DIRECTORY,
        false,
        shown_root,
    )?;
    open_regular_at(&dir, OsStr::new(parts[parts.len() - 1]), &shown)
}

/// What an entry below a directory handle is. The lookup is `fstatat` with
/// `AT_SYMLINK_NOFOLLOW`, so no part of the path is looked up again by name.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Dir,
    File,
    Link,
    Other,
}

/// The kind of `name` below `dir`, looked up relative to the handle itself.
/// `None` when there is no such entry.
pub(crate) fn stat_at(
    dir: &std::fs::File,
    name: &OsStr,
    shown: &str,
) -> Result<Option<Kind>, Refusal> {
    let name = c_name(name, shown)?;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            _ => Err(io(err, Path::new(shown))),
        };
    }
    let mode = (stat.st_mode as u32) & (libc::S_IFMT as u32);
    Ok(Some(match mode {
        m if m == libc::S_IFDIR as u32 => Kind::Dir,
        m if m == libc::S_IFREG as u32 => Kind::File,
        m if m == libc::S_IFLNK as u32 => Kind::Link,
        _ => Kind::Other,
    }))
}

/// The `errno` slot for this platform, so a null `readdir` result can be told
/// apart from the end of the folder.
fn errno() -> *mut libc::c_int {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        libc::__errno_location()
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    unsafe {
        libc::__error()
    }
}

#[cfg(test)]
thread_local! {
    /// A test names a folder-walk failure: report `EIO` after this many
    /// entries instead of the end of the folder. The walk must refuse.
    static READDIR_FAULT_AFTER: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn fail_readdir_after(entries: usize) {
    READDIR_FAULT_AFTER.with(|fault| fault.set(entries));
}

/// Every name in the opened directory `stream`, refusing a `readdir` error.
/// A null result means the end of the folder only when `errno` is zero.
fn read_dir_names(stream: *mut libc::DIR, shown: &str) -> Result<Vec<OsString>, Refusal> {
    let mut names = Vec::new();
    loop {
        unsafe { *errno() = 0 };
        #[cfg(test)]
        let faulted = READDIR_FAULT_AFTER.with(|fault| {
            let after = fault.get();
            after != 0 && names.len() >= after
        });
        #[cfg(not(test))]
        let faulted = false;
        if faulted {
            unsafe { *errno() = libc::EIO };
        }
        let entry = if faulted {
            std::ptr::null_mut()
        } else {
            unsafe { libc::readdir(stream) }
        };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(0) | None => Ok(names),
                Some(_) => Err(io(error, Path::new(shown))),
            };
        }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = OsStr::from_bytes(raw.to_bytes()).to_os_string();
        if name == "." || name == ".." {
            continue;
        }
        names.push(name);
    }
}

/// One regular file below a walked folder: its folder handle, name, path below
/// the walk's prefix and shown path.
pub(crate) type FileVisitor<'a> =
    dyn FnMut(&std::fs::File, &OsStr, &str, &str) -> Result<(), Refusal> + 'a;

/// Lists every regular file below `dir`, which is opened already. This is the
/// one walk `pack` and the listing share. It uses the directory handle for each
/// child (`fstatat`), opens each folder with `O_NOFOLLOW`, and refuses a
/// `readdir` error instead of treating it as the end of the folder, so a
/// bundle can never come out shorter than the folder it names. `visit` gets the
/// folder handle, the name, the `/`-separated path below `prefix`, and the
/// shown path of one regular file.
pub(crate) fn walk_regular_files(
    dir: &std::fs::File,
    prefix: &str,
    shown: &str,
    visit: &mut FileVisitor<'_>,
) -> Result<(), Refusal> {
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return Err(io(std::io::Error::last_os_error(), Path::new(shown)));
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe { libc::close(dup) };
        return Err(io(std::io::Error::last_os_error(), Path::new(shown)));
    }
    let names = read_dir_names(stream, shown);
    unsafe { libc::closedir(stream) };
    let mut names = names?;
    names.sort();
    for name in names {
        let shown_child = format!("{shown}/{}", name.to_string_lossy());
        let name_text = name
            .to_str()
            .ok_or_else(|| Refusal::PathInvalid(shown_child.clone()))?;
        check_segment(name_text)?;
        let relative = if prefix.is_empty() {
            name_text.to_string()
        } else {
            format!("{prefix}/{name_text}")
        };
        match stat_at(dir, &name, &shown_child)? {
            Some(Kind::Dir) => {
                let child = open_at(dir, &name, libc::O_RDONLY | libc::O_DIRECTORY, &shown_child)?;
                walk_regular_files(&child, &relative, &shown_child, visit)?;
            }
            Some(Kind::File) => visit(dir, &name, &relative, &shown_child)?,
            _ => return Err(Refusal::SpecialFile(relative)),
        }
    }
    Ok(())
}

pub(crate) fn check_segment(name: &str) -> Result<(), Refusal> {
    if name.is_empty() || name == "." || name == ".." {
        return Err(Refusal::PathInvalid(name.to_string()));
    }
    if name.contains(['/', '\\']) || name.chars().any(char::is_control) {
        return Err(Refusal::PathInvalid(name.escape_default().to_string()));
    }
    if !name.is_ascii() && !is_nfc(name) {
        return Err(Refusal::PathNotNfc(name.escape_unicode().to_string()));
    }
    Ok(())
}

/// The canonical listing document.
pub fn listing_bytes(entries: &[Entry]) -> Vec<u8> {
    let files: Vec<_> = entries
        .iter()
        .map(|entry| json!({ "path": entry.path, "size": entry.size, "sha256": entry.sha256 }))
        .collect();
    // serde_json's default map sorts keys, and `to_vec` writes no whitespace.
    serde_json::to_vec(&json!({ "schema": LISTING_SCHEMA, "files": files })).unwrap()
}

/// The CID that names the closure under `root`.
pub fn closure_cid(root: &Path) -> Result<(String, Vec<Entry>), Refusal> {
    let entries = list_closure(root)?;
    Ok((cid_of(&entries), entries))
}

pub(crate) fn cid_of(entries: &[Entry]) -> String {
    cid_v1_raw_sha256(&listing_bytes(entries))
}
