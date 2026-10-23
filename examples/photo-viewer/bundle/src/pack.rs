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
//! too (`symlink_in_path`). The destination is checked the same way, and must
//! not exist, before the first write: a refused pack writes nothing. The
//! result is checked by listing it, and its CID is returned.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::admit::{check_cid_form, parse_manifest};
use crate::listing::{check_prefixes, check_segment, closure_cid, real_path, walk};

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

    std::fs::create_dir_all(&into).map_err(|err| io(err, &into))?;
    for file in &files {
        let to = into.join(file);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(|err| io(err, parent))?;
        }
        std::fs::copy(source.join(file), &to).map_err(|err| io(err, &to))?;
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
    let manifest_to = into.join("capsule.json");
    std::fs::write(&manifest_to, shipped).map_err(|err| io(err, &manifest_to))?;
    closure_cid(&into)
}
