//! Admission: verify, then stage a read-only copy under its CID, verify the
//! copy, and load only from it.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use semver::Version;
use serde_json::Value;

use crate::listing::{cid_of, read_closure, Entry};
use crate::{io, Refusal, SignedClaim, TrustPolicy};

/// A capsule already in the person's inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub cid: String,
}

/// An admitted capsule, staged at `path` (`store/<cid>`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub cid: String,
    pub name: String,
    pub version: String,
    pub role: String,
    pub publisher_did: String,
    pub path: PathBuf,
}

/// A staged capsule that still hashes to its CID and is read-only.
#[derive(Clone, Debug, PartialEq)]
pub struct Loaded {
    pub cid: String,
    pub path: PathBuf,
    pub entries: Vec<Entry>,
    pub manifest: Value,
}

pub fn admit(
    source: &Path,
    claim: &SignedClaim,
    policy: &TrustPolicy,
    installed: &[Installed],
    store: &Path,
    now: u64,
) -> Result<Admitted, Refusal> {
    // 1. The closure, and its CID.
    let (entries, manifest) = read_closure(source)?;
    let computed = cid_of(&entries);
    let claimed = &claim.claim;
    if computed != claimed.cid {
        return Err(Refusal::CidMismatch {
            claimed: claimed.cid.clone(),
            computed,
        });
    }
    // 2. The publisher's signature over the claim.
    claim.verify()?;
    // 3. The claim says what the manifest says.
    let manifest = parse_manifest(&manifest)?;
    for (field, value) in [
        ("name", &claimed.name),
        ("version", &claimed.version),
        ("role", &claimed.role),
    ] {
        let in_manifest = manifest.get(field).and_then(Value::as_str);
        if in_manifest != Some(value.as_str()) {
            return Err(Refusal::ClaimManifestMismatch(format!(
                "claim {field} {value:?}, capsule.json {field} {in_manifest:?}"
            )));
        }
    }
    let offered = parse_version(&claimed.name, &claimed.version)?;
    // 4. A current policy, revocations, then the publisher's roles and names.
    if now >= policy.expires_at {
        return Err(Refusal::PolicyExpired {
            expires_at: policy.expires_at,
            now,
        });
    }
    // A newer policy may have been accepted since this one: it may revoke.
    match policy.floor.seen()? {
        Some((seen, seen_sha256))
            if seen < policy.sequence
                || (seen == policy.sequence && seen_sha256 == policy.sha256) => {}
        seen => {
            return Err(Refusal::PolicyStale {
                sequence: policy.sequence,
                seen: seen.map(|(seen, _)| seen),
            });
        }
    }
    if policy.revoked_cids.contains(&claimed.cid) {
        return Err(Refusal::CidRevoked(claimed.cid.clone()));
    }
    if policy.revoked_dids.contains(&claimed.publisher_did) {
        return Err(Refusal::PublisherRevoked(claimed.publisher_did.clone()));
    }
    let entry = policy
        .publishers
        .iter()
        .find(|entry| entry.did == claimed.publisher_did)
        .ok_or_else(|| Refusal::PublisherUntrusted(claimed.publisher_did.clone()))?;
    if let Some(expires_at) = entry.expires_at.filter(|expires_at| now >= *expires_at) {
        return Err(Refusal::DevKeyExpired {
            did: entry.did.clone(),
            expires_at,
        });
    }
    let role_allowed = entry.roles.contains(&claimed.role);
    let name_allowed = entry
        .names
        .as_ref()
        .is_none_or(|names| names.contains(&claimed.name));
    if !role_allowed || !name_allowed {
        return Err(Refusal::PublisherRoleRefused {
            publisher: claimed.publisher_did.clone(),
            role: claimed.role.clone(),
            name: claimed.name.clone(),
        });
    }
    // 5. Never a lower version of an installed name, and one CID per version.
    for current in installed
        .iter()
        .filter(|current| current.name == claimed.name)
    {
        let installed_version = parse_version(&current.name, &current.version)?;
        if installed_version > offered {
            return Err(Refusal::VersionDowngrade {
                name: claimed.name.clone(),
                installed: current.version.clone(),
                offered: claimed.version.clone(),
            });
        }
        if installed_version == offered && current.cid != claimed.cid {
            return Err(Refusal::VersionConflict {
                name: claimed.name.clone(),
                version: claimed.version.clone(),
                installed: current.cid.clone(),
                offered: claimed.cid.clone(),
            });
        }
    }
    // 6. Stage by CID, verify the copy, load from it.
    stage(source, &entries, &claimed.cid, store)?;
    let loaded = load(store, &claimed.cid)?;
    Ok(Admitted {
        cid: loaded.cid,
        name: claimed.name.clone(),
        version: claimed.version.clone(),
        role: claimed.role.clone(),
        publisher_did: claimed.publisher_did.clone(),
        path: loaded.path,
    })
}

/// Loads `store/<cid>` only if it still hashes to `cid` and nothing in it is
/// writable. Every launch goes through here, not through the source.
pub fn load(store: &Path, cid: &str) -> Result<Loaded, Refusal> {
    check_cid_form(cid)?;
    let path = store.join(cid);
    check_read_only(&path, &path)?;
    let (entries, manifest) = read_closure(&path)?;
    let computed = cid_of(&entries);
    if computed != cid {
        return Err(Refusal::StagedMismatch {
            cid: cid.to_string(),
            computed,
        });
    }
    let manifest = parse_manifest(&manifest)?;
    Ok(Loaded {
        cid: cid.to_string(),
        path,
        entries,
        manifest,
    })
}

/// The surface names its core by `requires[].cid` (review answer 7). A name
/// alone never selects a capsule.
pub fn resolve_requires(
    manifest: &Value,
    installed: &[Installed],
) -> Result<Vec<Installed>, Refusal> {
    let requires = manifest
        .get("requires")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut cores = Vec::new();
    for requirement in requires
        .iter()
        .filter(|r| r.get("kind").and_then(Value::as_str) == Some("capsule"))
    {
        let name = requirement
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let Some(cid) = requirement.get("cid").and_then(Value::as_str) else {
            return Err(Refusal::CoreUnpinned(name));
        };
        if let Some(core) = installed
            .iter()
            .find(|core| core.cid == cid && core.name == name)
        {
            cores.push(core.clone());
        } else if let Some(other) = installed
            .iter()
            .find(|core| core.name == name || core.cid == cid)
        {
            return Err(Refusal::CoreMismatch {
                name,
                required: cid.to_string(),
                installed: format!("{} {}", other.name, other.cid),
            });
        } else {
            return Err(Refusal::CoreMissing {
                name,
                cid: cid.to_string(),
            });
        }
    }
    Ok(cores)
}

pub(crate) fn parse_manifest(bytes: &[u8]) -> Result<Value, Refusal> {
    let manifest: Value = serde_json::from_slice(bytes)
        .map_err(|err| Refusal::ClaimMalformed(format!("capsule.json: {err}")))?;
    if !manifest.is_object() {
        return Err(Refusal::ClaimMalformed(
            "capsule.json is not an object".to_string(),
        ));
    }
    Ok(manifest)
}

fn parse_version(name: &str, version: &str) -> Result<Version, Refusal> {
    Version::parse(version)
        .map_err(|err| Refusal::ClaimMalformed(format!("{name} version {version:?}: {err}")))
}

/// `b` and base32 lower only, so a CID is one path segment.
pub(crate) fn check_cid_form(cid: &str) -> Result<(), Refusal> {
    let body = cid.strip_prefix('b').unwrap_or_default();
    if body.is_empty()
        || !body
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
    {
        return Err(Refusal::PathInvalid(format!("{cid:?} is not a CID")));
    }
    Ok(())
}

fn stage(source: &Path, entries: &[Entry], cid: &str, store: &Path) -> Result<(), Refusal> {
    std::fs::create_dir_all(store).map_err(|err| io(err, store))?;
    let target = store.join(cid);
    if target.exists() {
        // Already staged; `load` decides whether it is still good.
        return Ok(());
    }
    let staging = store.join(format!(
        ".staging-{}",
        hex::encode(rand::random::<[u8; 8]>())
    ));
    std::fs::create_dir(&staging).map_err(|err| io(err, &staging))?;
    let result = copy_and_seal(source, entries, cid, &staging)
        .and_then(|()| std::fs::rename(&staging, &target).map_err(|err| io(err, &target)));
    if result.is_err() {
        remove_staging(&staging);
    }
    result
}

fn copy_and_seal(
    source: &Path,
    entries: &[Entry],
    cid: &str,
    staging: &Path,
) -> Result<(), Refusal> {
    for entry in entries {
        let from = source.join(&entry.path);
        let to = staging.join(&entry.path);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(|err| io(err, parent))?;
        }
        let bytes = std::fs::read(&from).map_err(|err| io(err, &from))?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)
            .map_err(|err| io(err, &to))?;
        file.write_all(&bytes).map_err(|err| io(err, &to))?;
    }
    // The copy, not the source, is what must hash to the CID: a source that
    // changed after it was verified is caught here.
    let (copied, _) = read_closure(staging)?;
    let computed = cid_of(&copied);
    if computed != cid {
        return Err(Refusal::StagedMismatch {
            cid: cid.to_string(),
            computed,
        });
    }
    seal(staging)
}

/// Files 0444, directories 0555, deepest first.
fn seal(dir: &Path) -> Result<(), Refusal> {
    for child in std::fs::read_dir(dir).map_err(|err| io(err, dir))? {
        let path = child.map_err(|err| io(err, dir))?.path();
        let meta = std::fs::symlink_metadata(&path).map_err(|err| io(err, &path))?;
        if meta.is_dir() {
            seal(&path)?;
        } else {
            set_mode(&path, 0o444)?;
        }
    }
    set_mode(dir, 0o555)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), Refusal> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|err| io(err, path))
}

fn check_read_only(root: &Path, path: &Path) -> Result<(), Refusal> {
    let meta = std::fs::symlink_metadata(path).map_err(|err| io(err, path))?;
    if meta.permissions().mode() & 0o222 != 0 {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        return Err(Refusal::StagedNotReadOnly(if relative.is_empty() {
            ".".to_string()
        } else {
            relative
        }));
    }
    if meta.is_dir() {
        for child in std::fs::read_dir(path).map_err(|err| io(err, path))? {
            check_read_only(root, &child.map_err(|err| io(err, path))?.path())?;
        }
    }
    Ok(())
}

/// Best effort: make the half-built copy writable again and remove it.
fn remove_staging(dir: &Path) {
    fn unseal(path: &Path) {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            return;
        };
        if meta.is_dir() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755));
            if let Ok(children) = std::fs::read_dir(path) {
                for child in children.flatten() {
                    unseal(&child.path());
                }
            }
        } else if meta.is_file() {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
        }
    }
    unseal(dir);
    let _ = std::fs::remove_dir_all(dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that changes after it was listed and verified is not staged.
    #[test]
    fn a_source_changed_after_verification_is_not_staged() {
        let root = tempfile::tempdir().unwrap();
        // Real path: on macOS /var in the default temp path is a link, and the
        // closure check refuses a link anywhere on the way.
        let base = root.path().canonicalize().unwrap();
        let source = base.join("source");
        let store = base.join("store");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("capsule.json"), b"{}").unwrap();
        std::fs::write(source.join("a.wasm"), b"verified").unwrap();
        let (entries, _) = read_closure(&source).unwrap();
        let cid = cid_of(&entries);

        std::fs::write(source.join("a.wasm"), b"swapped!").unwrap();
        let refusal = stage(&source, &entries, &cid, &store).unwrap_err();
        assert_eq!(refusal.code(), "staged_mismatch", "{refusal}");
        assert!(!store.join(&cid).exists());
        let left: Vec<_> = std::fs::read_dir(&store).unwrap().collect();
        assert!(left.is_empty(), "the half-built copy is removed: {left:?}");
    }
}
