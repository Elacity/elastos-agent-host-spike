//! Pack: the closure a capsule ships, made out of its source folder.
//!
//! A source folder holds source, tests, fixtures and build output. Naming it
//! by CID would make the name change with any of them. `pack` copies only what
//! the capsule runs from into a new folder:
//! - `capsule.json`;
//! - for a page (`execution: web-projection`), every file in the folder of its
//!   entrypoint (for example all of `browser/`), which must not be the root;
//! - for anything else, the entrypoint file alone (for example the built
//!   `.component.wasm`).
//!
//! Each `(name, cid)` in `requires` becomes a `{name, kind: "capsule", cid}`
//! requirement on the packed manifest, replacing one of the same name: so a
//! page names its core by CID. Without `requires` the manifest is copied byte
//! for byte. Symlinks and special files are refused, never followed: every
//! component of every path is lstat'ed, from the source folder down, before
//! anything is read or copied, so a link in the middle of a path is refused
//! too (`symlink_in_path`). The copy opens each part again from the root with
//! a directory-relative `openat` and `O_NOFOLLOW`, so a folder swapped for a
//! link after the checks is refused by the open instead of read through. The
//! complete planned listing (the entrypoint's files and `capsule.json`) is
//! checked, and the destination must not exist, before the first write: a
//! refused pack writes nothing. The result is checked by listing it, and its
//! CID is returned.

use std::ffi::{CString, OsStr};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};

use crate::admit::{check_cid_form, parse_manifest};
use crate::listing::{
    check_prefixes, check_segment, check_unique_under_case_folding, closure_cid, real_path, walk,
};

/// The destination as its parts: no trailing `/` or `.`, no `..`, no link on
/// the way to it, and nothing there yet. The prefixes are checked by the same
/// check as the source, before the first write, so a refused pack writes
/// nothing and a retry with the physical path starts from a clean folder.
fn check_destination(into: &Path) -> Result<PathBuf, Refusal> {
    let into = check_prefixes(into)?;
    if std::fs::symlink_metadata(&into).is_ok() {
        return Err(Refusal::PackDestinationExists(into.display().to_string()));
    }
    Ok(into)
}

/// `name` for an `openat` call; a name with a NUL byte is not a path we made.
fn c_name(name: &OsStr, shown: &str) -> Result<CString, Refusal> {
    CString::new(name.as_bytes()).map_err(|_| Refusal::PathInvalid(shown.to_string()))
}

/// Opens `name` below `dir` with `flags` and `O_NOFOLLOW`, so a link swapped in
/// after the planning checks is refused by the open itself, not read through.
fn open_at(
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
fn open_dir(path: &Path) -> Result<std::fs::File, Refusal> {
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
fn open_in(
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

/// Makes the destination folder (its parts are checked already), then opens
/// it. Every level is created below the nearest existing one; a link swapped
/// in on the way is refused by the open.
fn create_destination(path: &Path) -> Result<std::fs::File, Refusal> {
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
        let name_c = c_name(name, &shown)?;
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o755) } < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(io(err, Path::new(&shown)));
            }
        }
        dir = open_at(&dir, name, libc::O_RDONLY | libc::O_DIRECTORY, &shown)?;
    }
    Ok(dir)
}

/// lstats `source`, then each segment below it, in order. `source` and every
/// segment but the last must be real folders, never links: a link anywhere on
/// the way would make every check after it describe another place. The last
/// segment's metadata is returned for the caller to check (it is not
/// followed either). `None` when a segment does not exist, or a file stands
/// where a folder should.
fn lstat_each(source: &Path, segments: &[&str]) -> Result<Option<std::fs::Metadata>, Refusal> {
    let mut path = source.to_path_buf();
    let mut shown = source.display().to_string();
    let mut meta = std::fs::symlink_metadata(&path).map_err(|err| io(err, &path))?;
    for segment in segments {
        if meta.file_type().is_symlink() {
            return Err(Refusal::SymlinkInPath(shown));
        }
        if !meta.is_dir() {
            return Ok(None);
        }
        path.push(segment);
        shown = format!("{shown}/{segment}");
        meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(_) => return Ok(None),
        };
    }
    Ok(Some(meta))
}
use crate::{io, Entry, Refusal};

pub fn pack(
    source: &Path,
    into: &Path,
    requires: &[(String, String)],
) -> Result<(String, Vec<Entry>), Refusal> {
    pack_inner(source, into, requires, || {})
}

/// [`pack`], with `after_plan` run once the planned listing and the
/// destination are checked and before the first open for reading or writing.
/// Tests use the window to swap a checked folder for a link; `pack` passes a
/// no-op.
fn pack_inner<F: FnOnce()>(
    source: &Path,
    into: &Path,
    requires: &[(String, String)],
    after_plan: F,
) -> Result<(String, Vec<Entry>), Refusal> {
    // The source as its parts: no trailing `/` or `.`, no `..`, no link on the way.
    let (source, _) = real_path(source)?;
    let source = source.as_path();
    let manifest_path = source.join("capsule.json");
    let manifest_bytes = match lstat_each(source, &["capsule.json"])? {
        Some(meta) if meta.is_file() => {
            std::fs::read(&manifest_path).map_err(|err| io(err, &manifest_path))?
        }
        Some(_) => return Err(Refusal::SpecialFile("capsule.json".to_string())),
        None => return Err(Refusal::ManifestMissing),
    };
    let mut manifest = parse_manifest(&manifest_bytes)?;
    let entrypoint = manifest
        .get("entrypoint")
        .and_then(Value::as_str)
        .filter(|entrypoint| !entrypoint.is_empty())
        .ok_or_else(|| Refusal::PackEntrypointMissing("capsule.json names no entrypoint".into()))?
        .to_string();
    let segments: Vec<&str> = entrypoint.split('/').collect();
    for segment in &segments {
        check_segment(segment)?;
    }
    for (name, cid) in requires {
        check_cid_form(cid)?;
        if name.is_empty() {
            return Err(Refusal::ClaimMalformed("a requirement with no name".into()));
        }
    }
    let into = check_destination(into)?;

    // What ships, as paths relative to the source.
    let mut files: Vec<String> = Vec::new();
    if manifest.get("execution").and_then(Value::as_str) == Some("web-projection") {
        if segments.len() < 2 {
            return Err(Refusal::PackEntrypointMissing(format!(
                "a page's entrypoint must be in a folder of its own, not {entrypoint}"
            )));
        }
        let folder = segments[..segments.len() - 1].join("/");
        let root = source.join(&folder);
        match lstat_each(source, &segments[..segments.len() - 1])? {
            // The folder itself is walked, so it must not be a link either.
            Some(meta) if meta.file_type().is_symlink() => {
                return Err(Refusal::SymlinkInPath(root.display().to_string()))
            }
            Some(meta) if meta.is_dir() => {}
            _ => {
                return Err(Refusal::PackEntrypointMissing(format!(
                    "{folder} is not a folder"
                )))
            }
        }
        let mut entries = Vec::new();
        let mut none = None;
        walk(&root, &root, &mut entries, &mut none)?;
        files.extend(
            entries
                .into_iter()
                .map(|entry| format!("{folder}/{}", entry.path)),
        );
        if !files.contains(&entrypoint) {
            return Err(Refusal::PackEntrypointMissing(format!(
                "{entrypoint} is not in the source"
            )));
        }
    } else {
        match lstat_each(source, &segments)? {
            Some(meta) if meta.is_file() => files.push(entrypoint.clone()),
            Some(_) => return Err(Refusal::SpecialFile(entrypoint)),
            None => {
                return Err(Refusal::PackEntrypointMissing(format!(
                    "{entrypoint} is not in the source; build it first"
                )))
            }
        }
    }

    // The complete listing this pack would make, checked before the first
    // write: the entrypoint's files and the manifest name one set of paths,
    // and two that fold together would not describe what lands on disk.
    let mut planned: Vec<&str> = Vec::with_capacity(files.len() + 1);
    planned.push("capsule.json");
    planned.extend(
        files
            .iter()
            .filter(|file| *file != "capsule.json")
            .map(String::as_str),
    );
    check_unique_under_case_folding(planned)?;
    after_plan();

    let source_dir = open_dir(source)?;
    let mut destination: Option<std::fs::File> = None;
    for file in &files {
        // The source is opened first, so a link swapped in on the way is
        // refused before the destination exists.
        let mut from = open_in(
            &source_dir,
            file,
            libc::O_RDONLY,
            false,
            &source.display().to_string(),
        )?;
        let dir = match destination.take() {
            Some(dir) => dir,
            None => create_destination(&into)?,
        };
        let mut to = open_in(
            &dir,
            file,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            true,
            &into.display().to_string(),
        )?;
        std::io::copy(&mut from, &mut to).map_err(|err| io(err, &into.join(file)))?;
        destination = Some(dir);
    }
    let shipped = if requires.is_empty() {
        manifest_bytes
    } else {
        let mut list: Vec<Value> = manifest
            .get("requires")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (name, cid) in requires {
            list.retain(|requirement| {
                requirement.get("name").and_then(Value::as_str) != Some(name)
            });
            list.push(json!({ "name": name, "kind": "capsule", "cid": cid }));
        }
        manifest["requires"] = Value::Array(list);
        let mut bytes = serde_json::to_vec_pretty(&manifest).expect("a manifest serializes");
        bytes.push(b'\n');
        bytes
    };
    let destination = match destination {
        Some(dir) => dir,
        None => create_destination(&into)?,
    };
    let mut manifest_file = open_in(
        &destination,
        "capsule.json",
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        true,
        &into.display().to_string(),
    )?;
    manifest_file
        .write_all(&shipped)
        .map_err(|err| io(err, &into.join("capsule.json")))?;
    closure_cid(&into)
}

/// A race test lives here, not in `tests/`: it needs the window between the
/// planning checks and the first copy, which only [`pack_inner`] exposes.
#[cfg(test)]
mod tests {
    use super::*;

    struct Temp(#[allow(dead_code)] tempfile::TempDir, PathBuf);

    impl Temp {
        fn path(&self) -> &Path {
            &self.1
        }
    }

    fn tempdir() -> Temp {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().canonicalize().unwrap();
        Temp(dir, real)
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn pack_refuses_a_source_folder_swapped_for_a_link_after_checking() {
        let root = tempdir();
        let r = root.path();
        let page = r.join("page");
        write(
            &page.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"viewer","execution":"web-projection","entrypoint":"browser/index.html"}"#,
        );
        write(&page.join("browser/index.html"), b"<!doctype html> inside");
        // Bytes outside the source that a followed link would ship.
        write(&r.join("outside/index.html"), b"<!doctype html> outside");

        // The checks pass on the real folder; the swap lands before the copy,
        // as a concurrent writer could. The open must refuse the link, not
        // read and copy through it.
        let into = r.join("packed");
        let refusal = pack_inner(&page, &into, &[], || {
            std::fs::rename(page.join("browser"), page.join("browser-real")).unwrap();
            std::os::unix::fs::symlink(r.join("outside"), page.join("browser")).unwrap();
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "symlink_in_path");
        assert!(!into.exists(), "{} was written", into.display());
    }
}
