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

use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

use serde_json::{json, Value};

use crate::admit::{check_cid_form, parse_manifest};
use crate::listing::{
    c_name, check_prefixes, check_segment, check_unique_under_case_folding, closure_cid, open_at,
    open_dir, open_in, open_regular_in, real_path, stat_at, walk_regular_files, Kind,
};

/// The destination as its parts: no trailing `/` or `.`, no `..`, no link on
/// the way to it, and at least one part that names a new folder. `.` and `/`
/// name folders that already exist, so there is no new folder to create
/// exclusively and nothing to pack into: they are refused
/// (`pack_destination_exists`) with the folder and its contents untouched.
fn check_destination(into: &Path) -> Result<PathBuf, Refusal> {
    let rebuilt = check_prefixes(into)?;
    let names_a_folder = rebuilt
        .components()
        .any(|part| matches!(part, Component::Normal(_)));
    if !names_a_folder {
        return Err(Refusal::PackDestinationExists(
            rebuilt.display().to_string(),
        ));
    }
    Ok(rebuilt)
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
    let mut file = open_regular_in(source_dir, "capsule.json", shown_root)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|err| io(err, Path::new(&shown)))?;
    Ok(bytes)
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
        walk_regular_files(
            &folder_dir,
            &folder,
            &root.display().to_string(),
            &mut |_, _, relative, _| {
                files.push(relative.to_string());
                Ok(())
            },
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
            open_regular_in(&source_dir, file, &source.display().to_string())?,
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
    use crate::testing::refused;

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

    fn component_source(dir: &Path) -> PathBuf {
        write(
            &dir.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"app","execution":"component","entrypoint":"x.component.wasm"}"#,
        );
        write(&dir.join("x.component.wasm"), b"\0asm component");
        dir.to_path_buf()
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

    /// Clears the injected folder-walk failure at the end of a test, also when
    /// the test panics.
    struct ReadDirFault;

    impl Drop for ReadDirFault {
        fn drop(&mut self) {
            crate::listing::fail_readdir_after(0);
        }
    }

    #[test]
    fn pack_refuses_a_destination_that_names_no_new_folder() {
        let root = tempdir();
        let r = root.path();
        let core = component_source(&r.join("core"));
        std::fs::write(r.join("sentinel.txt"), b"keep").unwrap();

        // Packing into `.` or `/` cannot create a new folder exclusively, so
        // there is no destination to adopt: both are refused and the current
        // folder keeps its contents.
        let back = std::env::current_dir().unwrap();
        std::env::set_current_dir(r).unwrap();
        let dot = pack(&core, Path::new("."), &[]);
        let slash = pack(&core, Path::new("/"), &[]);
        std::env::set_current_dir(back).unwrap();

        assert_eq!(refused(dot), "pack_destination_exists");
        assert_eq!(refused(slash), "pack_destination_exists");
        assert_eq!(std::fs::read(r.join("sentinel.txt")).unwrap(), b"keep");
        assert!(!r.join("capsule.json").exists(), "the manifest was written");
        assert!(
            !r.join("x.component.wasm").exists(),
            "the entrypoint was written"
        );
    }

    #[test]
    fn pack_refuses_a_source_file_replaced_by_a_folder_after_planning() {
        let root = tempdir();
        let r = root.path();
        let core = component_source(&r.join("core"));
        let wasm = core.join("x.component.wasm");
        let into = r.join("packed");

        // The planned listing passed with a regular file; a folder takes its
        // place before the sources are opened. The handle must be refused as
        // a special file, not copied into a new destination.
        let refusal = pack_inner(&core, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Plan) {
                std::fs::remove_file(&wasm).unwrap();
                std::fs::create_dir(&wasm).unwrap();
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "special_file");
        assert!(!into.exists(), "{} was written", into.display());
    }

    #[test]
    fn pack_refuses_a_source_file_replaced_by_a_fifo_after_planning() {
        use std::os::unix::ffi::OsStrExt;

        let root = tempdir();
        let r = root.path();
        let core = component_source(&r.join("core"));
        let wasm = core.join("x.component.wasm");
        let into = r.join("packed");
        let (ready, opened) = std::sync::mpsc::channel();
        let mut holder = None;

        // The planned listing passed with a regular file; a FIFO takes its
        // place before the sources are opened. A blocking open would wait for
        // a writer forever, so the opened handle must be checked instead. The
        // holder makes the old blocking open return when a mutant needs it to.
        let refusal = pack_inner(&core, &into, &[], &mut |hook| {
            if matches!(hook, Hook::Plan) {
                std::fs::remove_file(&wasm).unwrap();
                let name = std::ffi::CString::new(wasm.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                let path = wasm.clone();
                let ready = ready.clone();
                holder = Some(std::thread::spawn(move || {
                    let held = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&path)
                        .unwrap();
                    ready.send(()).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(800));
                    drop(held);
                }));
            }
        })
        .unwrap_err();
        assert_eq!(refusal.code(), "special_file");
        assert!(!into.exists(), "{} was written", into.display());
        opened
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        holder.unwrap().join().unwrap();
    }

    #[test]
    fn pack_refuses_a_folder_read_error_instead_of_sending_part_of_it() {
        let _fault = ReadDirFault;
        let root = tempdir();
        let r = root.path();
        let page = r.join("page");
        write(
            &page.join("capsule.json"),
            br#"{"schema":"elastos.capsule/v1","name":"x","version":"0.1.0","role":"viewer","execution":"web-projection","entrypoint":"browser/index.html"}"#,
        );
        write(&page.join("browser/index.html"), b"<!doctype html>");
        write(&page.join("browser/main.js"), b"// main");
        write(&page.join("browser/page.css"), b"main {}");

        // The folder walk returns index.html, then reports EIO instead of the
        // end of the folder. Treating that as the end would ship a bundle with
        // the remaining assets missing and report success; it must refuse and
        // write nothing.
        crate::listing::fail_readdir_after(3);
        let into = r.join("packed");
        let refusal = pack(&page, &into, &[]).unwrap_err();
        assert_eq!(refusal.code(), "io");
        assert!(!into.exists(), "{} was written", into.display());
    }
}
