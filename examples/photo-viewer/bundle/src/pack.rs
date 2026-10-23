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
//! too (`symlink_in_path`). The manifest read, the page planning walk and the
//! copy all use the opened source folder with directory-relative `openat` and
//! `fstatat` (`O_NOFOLLOW`), so planning never looks a path up again by name
//! and a folder swapped for a link after the checks is refused instead of read
//! through. The complete planned listing (the entrypoint's files and
//! `capsule.json`) is checked before the first write, and the destination is
//! created exclusively: a folder that appears after the check is refused
//! (`pack_destination_exists`) with its contents untouched. Every source file
//! is opened before the destination exists, so a refusal leaves no partial
//! output and a retry starts clean. The result is checked by listing it, and
//! its CID is returned.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};

use crate::admit::{check_cid_form, parse_manifest};
use crate::listing::{
    check_prefixes, check_segment, check_unique_under_case_folding, closure_cid, real_path,
};

/// The destination as its parts: no trailing `/` or `.`, no `..`, no link on
/// the way to it. The parts are checked by the same check as the source,
/// before the first write. The last level is created exclusively, so a folder
/// that appears after this check is refused (`pack_destination_exists`) with
/// its contents untouched.
fn check_destination(into: &Path) -> Result<PathBuf, Refusal> {
    check_prefixes(into)
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
/// it. Parent levels are created below the nearest existing one; the last
/// level must be created here, so a folder that appears after the checks is
/// refused instead of adopted. A link swapped in on the way is refused by the
/// open.
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
    let names: Vec<&OsStr> = path
        .components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    for (index, name) in names.iter().enumerate() {
        shown = format!("{shown}/{}", name.to_string_lossy());
        let last = index + 1 == names.len();
        let name_c = c_name(name, &shown)?;
        if unsafe { libc::mkdirat(dir.as_raw_fd(), name_c.as_ptr(), 0o755) } < 0 {
            let err = std::io::Error::last_os_error();
            if last && err.raw_os_error() == Some(libc::EEXIST) {
                return Err(Refusal::PackDestinationExists(shown));
            }
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
/// What an entry below a directory handle is. The lookup is `fstatat` with
/// `AT_SYMLINK_NOFOLLOW`, so no part of the path is looked up again by name.
#[derive(Clone, Copy)]
enum Kind {
    Dir,
    File,
    Link,
    Other,
}

/// The kind of `name` below `dir`, looked up relative to the handle itself.
/// `None` when there is no such entry.
fn stat_at(dir: &std::fs::File, name: &OsStr, shown: &str) -> Result<Option<Kind>, Refusal> {
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

/// Reads `capsule.json` below the opened source folder. The lookup, the type
/// check and the read all use the directory handle, so a manifest swapped for
/// a link after the planning `lstat` is refused by the open.
fn read_manifest(source_dir: &std::fs::File, shown_root: &str) -> Result<Vec<u8>, Refusal> {
    let shown = format!("{shown_root}/capsule.json");
    match stat_at(source_dir, OsStr::new("capsule.json"), &shown)? {
        None => return Err(Refusal::ManifestMissing),
        Some(Kind::File) => {}
        Some(Kind::Link) => return Err(Refusal::SymlinkInPath(shown)),
        Some(_) => return Err(Refusal::SpecialFile("capsule.json".to_string())),
    }
    let mut file = open_in(
        source_dir,
        "capsule.json",
        libc::O_RDONLY,
        false,
        shown_root,
    )?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| io(err, Path::new(&shown)))?;
    Ok(bytes)
}

/// Lists every regular file below `dir`, which is opened already. The walk
/// uses the directory handle for each child (`fstatat`) and opens each folder
/// with `O_NOFOLLOW`, so a folder swapped for a link after the planning
/// `lstat` is refused instead of walked. Paths are relative to `prefix`.
fn list_files_below(
    dir: &std::fs::File,
    prefix: &str,
    files: &mut Vec<String>,
    shown: &str,
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
    let mut names: Vec<OsString> = Vec::new();
    loop {
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break;
        }
        let raw = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = OsStr::from_bytes(raw.to_bytes()).to_os_string();
        if name == "." || name == ".." {
            continue;
        }
        names.push(name);
    }
    unsafe { libc::closedir(stream) };
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
                list_files_below(&child, &relative, files, &shown_child)?;
            }
            Some(Kind::File) => files.push(relative),
            _ => return Err(Refusal::SpecialFile(relative)),
        }
    }
    Ok(())
}

/// The points where a test can act after a check and before the work it
/// protects. [`pack`] passes a no-op.
enum Hook {
    /// The manifest's `lstat` passed; the manifest read follows.
    Manifest,
    /// The page folder's `lstat` passed; the planning walk follows.
    Entrypoint,
    /// The planned listing and the destination check passed; the first read
    /// or write follows.
    Plan,
}

use crate::{io, Entry, Refusal};

pub fn pack(
    source: &Path,
    into: &Path,
    requires: &[(String, String)],
) -> Result<(String, Vec<Entry>), Refusal> {
    pack_inner(source, into, requires, &mut |_| {})
}

/// [`pack`], with `hook` run at each check boundary before the work it
/// protects. Tests use the windows to swap a checked path; `pack` passes a
/// no-op.
fn pack_inner(
    source: &Path,
    into: &Path,
    requires: &[(String, String)],
    hook: &mut dyn FnMut(Hook),
) -> Result<(String, Vec<Entry>), Refusal> {
    // The source as its parts: no trailing `/` or `.`, no `..`, no link on the way.
    let (source, _) = real_path(source)?;
    let source = source.as_path();
    let source_dir = open_dir(source)?;
    let manifest_bytes = match lstat_each(source, &["capsule.json"])? {
        Some(meta) if meta.is_file() => {
            hook(Hook::Manifest);
            read_manifest(&source_dir, &source.display().to_string())?
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
        hook(Hook::Entrypoint);
        let folder_dir = open_in(
            &source_dir,
            &folder,
            libc::O_RDONLY | libc::O_DIRECTORY,
            false,
            &source.display().to_string(),
        )?;
        list_files_below(
            &folder_dir,
            &folder,
            &mut files,
            &root.display().to_string(),
        )?;
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
    hook(Hook::Plan);

    // Every source file is opened before the destination exists, so a later
    // link swapped in is refused with nothing written.
    let mut sources = Vec::with_capacity(files.len());
    for file in &files {
        sources.push((
            file,
            open_in(
                &source_dir,
                file,
                libc::O_RDONLY,
                false,
                &source.display().to_string(),
            )?,
        ));
    }
    let destination = create_destination(&into)?;
    for (file, mut from) in sources {
        // The manifest is written from the bytes read above, after the files.
        if file == "capsule.json" {
            continue;
        }
        let mut to = open_in(
            &destination,
            file,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            true,
            &into.display().to_string(),
        )?;
        std::io::copy(&mut from, &mut to).map_err(|err| io(err, &into.join(file)))?;
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
    let mut manifest_file = open_in(
        &destination,
        "capsule.json",
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
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
        let refusal = pack_inner(&page, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Plan) {
                std::fs::rename(page.join("browser"), page.join("browser-real")).unwrap();
                std::os::unix::fs::symlink(r.join("outside"), page.join("browser")).unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "symlink_in_path");
        assert!(!into.exists(), "{} was written", into.display());
    }

    #[test]
    fn pack_refuses_a_manifest_swapped_for_a_link_after_checking() {
        let root = tempdir();
        let r = root.path();
        let core = r.join("core");
        write(
            &core.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"inside","version":"0.1.0","role":"app","execution":"component","entrypoint":"x.component.wasm"}"#,
        );
        write(&core.join("x.component.wasm"), b"\0asm inside");
        // A valid manifest outside the source: a path read would parse and
        // ship this one instead of the source's.
        write(
            &r.join("outside/capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"outside","version":"0.1.0","role":"app","execution":"component","entrypoint":"x.component.wasm"}"#,
        );

        // The manifest's lstat passed; the swap lands before its read, as a
        // concurrent writer could. The read must refuse the link, not follow.
        let into = r.join("packed");
        let refusal = pack_inner(&core, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Manifest) {
                std::fs::rename(core.join("capsule.json"), core.join("manifest-real")).unwrap();
                std::os::unix::fs::symlink(
                    r.join("outside/capsule.json"),
                    core.join("capsule.json"),
                )
                .unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "symlink_in_path");
        assert!(!into.exists(), "{} was written", into.display());
    }

    #[test]
    fn pack_refuses_a_page_folder_swapped_for_a_link_during_planning() {
        let root = tempdir();
        let r = root.path();
        let page = r.join("page");
        write(
            &page.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"viewer","execution":"web-projection","entrypoint":"browser/index.html"}"#,
        );
        write(&page.join("browser/index.html"), b"<!doctype html> inside");
        write(&page.join("browser/main.js"), b"// inside");
        // The outside folder holds a link, which a path walk would report as
        // a special file after following the swapped page folder.
        write(&r.join("outside/browser/main.js"), b"// outside");
        std::os::unix::fs::symlink("/etc/hostname", r.join("outside/browser/index.html")).unwrap();

        // The page folder's lstat passed; the swap lands before the planning
        // walk. The walk must refuse the link itself, not list through it.
        let into = r.join("packed");
        let refusal = pack_inner(&page, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Entrypoint) {
                std::fs::rename(page.join("browser"), page.join("browser-real")).unwrap();
                std::os::unix::fs::symlink(r.join("outside/browser"), page.join("browser"))
                    .unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "symlink_in_path");
        assert!(!into.exists(), "{} was written", into.display());
    }

    #[test]
    fn pack_refuses_a_destination_created_after_validation() {
        let root = tempdir();
        let r = root.path();
        let core = r.join("core");
        write(
            &core.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"app","execution":"component","entrypoint":"x.component.wasm"}"#,
        );
        write(&core.join("x.component.wasm"), b"\0asm inside");

        // The destination did not exist at the check; another writer creates
        // it before the first write. It must be refused, with its contents
        // unchanged.
        let into = r.join("packed");
        let refusal = pack_inner(&core, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Plan) {
                std::fs::create_dir(&into).unwrap();
                std::fs::write(into.join("capsule.json"), b"sentinel").unwrap();
                std::fs::write(into.join("unrelated.txt"), b"keep").unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "pack_destination_exists");
        assert_eq!(
            std::fs::read(into.join("capsule.json")).unwrap(),
            b"sentinel"
        );
        assert_eq!(std::fs::read(into.join("unrelated.txt")).unwrap(), b"keep");
        assert!(!into.join("x.component.wasm").exists());
    }

    #[test]
    fn pack_refuses_a_later_link_without_leaving_partial_output() {
        let root = tempdir();
        let r = root.path();
        let page = r.join("page");
        write(
            &page.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"viewer","execution":"web-projection","entrypoint":"browser/index.html"}"#,
        );
        write(&page.join("browser/index.html"), b"<!doctype html>");
        write(&page.join("browser/main.js"), b"// main");
        write(&page.join("browser/styles/page.css"), b"main {}");
        std::fs::create_dir_all(r.join("outside/styles")).unwrap();

        // The first pages are still valid; a later folder is swapped for a
        // link. Every source is opened before the destination exists, so the
        // refusal leaves no partial output and a retry starts clean.
        let into = r.join("packed");
        let refusal = pack_inner(&page, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Plan) {
                std::fs::rename(page.join("browser/styles"), page.join("styles-real")).unwrap();
                std::os::unix::fs::symlink(r.join("outside/styles"), page.join("browser/styles"))
                    .unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "symlink_in_path");
        assert!(!into.exists(), "{} was written", into.display());
        // The clean destination makes the retry after the refusal succeed.
        std::fs::remove_file(page.join("browser/styles")).unwrap();
        std::fs::rename(page.join("styles-real"), page.join("browser/styles")).unwrap();
        let (_, entries) = pack(&page, &into, &[]).unwrap();
        assert_eq!(entries.len(), 4);
    }
}
