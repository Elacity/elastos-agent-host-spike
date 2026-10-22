//! The closure listing: every file a capsule ships, as canonical JSON.
//!
//! `{"files":[{"path","sha256","size"}...],"schema":"elastos.capsule.closure/v1"}`,
//! files sorted by path bytes, keys sorted, no whitespace. The keys are ASCII
//! and no path may hold a control character, so this is also the RFC 8785
//! (JCS) form of the document.

use std::collections::BTreeMap;
use std::path::Path;

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
    let mut entries = Vec::new();
    let mut manifest = None;
    walk(root, root, &mut entries, &mut manifest)?;
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    check_unique_under_case_folding(entries.iter().map(|entry| entry.path.as_str()))?;
    let manifest = manifest.ok_or(Refusal::ManifestMissing)?;
    Ok((entries, manifest))
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

pub(crate) fn walk(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<Entry>,
    manifest: &mut Option<Vec<u8>>,
) -> Result<(), Refusal> {
    let mut children: Vec<_> = std::fs::read_dir(dir)
        .map_err(|err| io(err, dir))?
        .collect::<Result<_, _>>()
        .map_err(|err| io(err, dir))?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let path = child.path();
        let relative = relative_path(root, &path)?;
        // lstat: a symlink is reported as itself, never followed.
        let meta = std::fs::symlink_metadata(&path).map_err(|err| io(err, &path))?;
        let kind = meta.file_type();
        if kind.is_dir() {
            walk(root, &path, entries, manifest)?;
        } else if kind.is_file() {
            if meta.len() > MAX_EXACT_SIZE {
                return Err(Refusal::PathInvalid(format!(
                    "{relative} is too large to list"
                )));
            }
            let bytes = std::fs::read(&path).map_err(|err| io(err, &path))?;
            entries.push(Entry {
                path: relative.clone(),
                size: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            });
            if relative == "capsule.json" {
                *manifest = Some(bytes);
            }
        } else {
            return Err(Refusal::SpecialFile(relative));
        }
    }
    Ok(())
}

/// `/`-separated, each segment checked.
fn relative_path(root: &Path, path: &Path) -> Result<String, Refusal> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| Refusal::PathInvalid(path.display().to_string()))?;
    let mut segments = Vec::new();
    for part in relative.components() {
        let std::path::Component::Normal(name) = part else {
            return Err(Refusal::PathInvalid(relative.display().to_string()));
        };
        let name = name
            .to_str()
            .ok_or_else(|| Refusal::PathInvalid(format!("{} is not UTF-8", relative.display())))?;
        check_segment(name)?;
        segments.push(name);
    }
    Ok(segments.join("/"))
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
