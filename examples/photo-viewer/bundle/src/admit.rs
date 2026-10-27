//! Admission: verify, then stage a read-only copy under its CID, verify the
//! copy, and load only from it.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use semver::Version;
use serde_json::{json, Value};

use crate::listing::{cid_of, read_closure, ClosureRead, Entry};
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
    /// This test code stands in for the Runtime's launch by CID, which does not exist yet.
    /// The same bytes that were hashed, keyed by closure entry path.
    pub bytes: BTreeMap<String, Vec<u8>>,
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
    let ClosureRead {
        entries, manifest, ..
    } = read_closure(source)?;
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
    // This test code stands in for the Runtime's launch by CID, which does not exist yet.
    if let Err(err) = std::fs::symlink_metadata(&path) {
        if err.kind() == std::io::ErrorKind::NotFound {
            return Err(Refusal::StagedMissing {
                cid: cid.to_string(),
            });
        }
        return Err(io(err, &path));
    }
    check_read_only(&path, &path)?;
    let ClosureRead {
        entries,
        manifest,
        bytes,
    } = read_closure(&path)?;
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
        bytes,
    })
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
/// Re-admit staged content with its detached claim and the current policy.
pub fn admit_staged_for_stand_in(
    loaded: &Loaded,
    claims: &BTreeMap<String, SignedClaim>,
    policy: &TrustPolicy,
    installed: &[Installed],
    store: &Path,
    now: u64,
) -> Result<Admitted, Refusal> {
    let Some(claim) = claims.get(&loaded.cid) else {
        return Err(Refusal::ClaimMissing {
            cid: loaded.cid.clone(),
        });
    };
    admit(&loaded.path, claim, policy, installed, store, now)
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandInDependencies {
    pub viewer: Admitted,
    pub core: Admitted,
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
/// Resolve and re-admit the pinned viewer and core before any launch.
#[allow(clippy::too_many_arguments)]
pub fn select_stand_in_dependencies(
    content: &Loaded,
    selected_viewer: &str,
    selected_core: &str,
    claims: &BTreeMap<String, SignedClaim>,
    policy: &TrustPolicy,
    installed: &[Installed],
    store: &Path,
    now: u64,
) -> Result<StandInDependencies, Refusal> {
    let viewers = resolve_requires((&content.manifest, content.cid.as_str()), installed)?;
    if viewers.len() != 1 {
        return Err(Refusal::LaunchBindingInvalid {
            cid: content.cid.clone(),
            role: "viewer".to_string(),
        });
    }
    let resolved_viewer = &viewers[0];
    if resolved_viewer.cid != selected_viewer {
        return Err(Refusal::ViewerMismatch {
            cid: content.cid.clone(),
            actual: resolved_viewer.cid.clone(),
            expected: selected_viewer.to_string(),
        });
    }
    let viewer_loaded = load(store, &resolved_viewer.cid)?;
    let viewer = admit_staged_for_stand_in(&viewer_loaded, claims, policy, installed, store, now)?;
    stand_in_selection_holds(
        &resolved_viewer.cid,
        &resolved_viewer.cid,
        "viewer",
        &viewer.role,
        viewer_loaded.manifest["execution"]
            .as_str()
            .unwrap_or_default(),
    )?;

    let cores = resolve_requires(&viewer_loaded.manifest, installed)?;
    if cores.len() != 1 {
        return Err(Refusal::LaunchBindingInvalid {
            cid: resolved_viewer.cid.clone(),
            role: "app".to_string(),
        });
    }
    let resolved_core = &cores[0];
    let core_loaded = load(store, &resolved_core.cid)?;
    let core = admit_staged_for_stand_in(&core_loaded, claims, policy, installed, store, now)?;
    stand_in_selection_holds(
        &resolved_core.cid,
        selected_core,
        "app",
        &core.role,
        core_loaded.manifest["execution"]
            .as_str()
            .unwrap_or_default(),
    )?;
    Ok(StandInDependencies { viewer, core })
}

// This test code stands in for the Runtime's launch by CID, which does not exist yet.
fn stand_in_selection_holds(
    resolved_cid: &str,
    selected_cid: &str,
    role: &str,
    admitted_role: &str,
    execution: &str,
) -> Result<(), Refusal> {
    let required_execution = if role == "viewer" {
        "web-projection"
    } else {
        "component"
    };
    if resolved_cid != selected_cid || admitted_role != role || execution != required_execution {
        return Err(Refusal::LaunchBindingInvalid {
            cid: resolved_cid.to_string(),
            role: role.to_string(),
        });
    }
    Ok(())
}

// This test code stands in for the Runtime's launch by CID, which does not exist yet.
// Compile the kit's URI owner directly: this slice adds no dependency or copied rule.
#[path = "../../../capsule-kit/guest/src/uri.rs"]
mod stand_in_uri;

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
/// Bind image members to the bytes already checked by `load`. Admission and
/// execution remain separate steps for the caller.
pub fn bind_content_stand_in(loaded: &Loaded) -> Result<BTreeMap<String, Vec<u8>>, Refusal> {
    let binding_invalid = |detail| Refusal::ContentBindingInvalid {
        cid: loaded.cid.clone(),
        detail,
    };
    let mut objects = BTreeMap::new();
    for entry in &loaded.entries {
        let path = entry.path.as_str();
        if !path.starts_with("images/") {
            continue;
        }
        let uri = format!(
            "localhost://Users/self/Pictures/Capsules/{}/{path}",
            loaded.cid
        );
        if let Err(reason) =
            stand_in_uri::check_object_uri(&uri, "localhost://Users/self/Pictures/")
        {
            return Err(binding_invalid(format!("{path}: {reason}")));
        }
        let bytes = loaded.bytes.get(path).cloned().ok_or_else(|| {
            binding_invalid(format!("{path}: loaded bytes have no entry for this path"))
        })?;
        objects.insert(uri, bytes);
    }
    Ok(objects)
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
/// Optional closure identity for diagnostics. A bare manifest has no closure
/// CID; callers with a packed/loaded closure pass `(&manifest, cid.as_str())`.
/// This context supplies neither admission nor execution permission.
pub struct StandInResolveManifest<'a> {
    manifest: &'a Value,
    cid: &'a str,
}

impl<'a> From<&'a Value> for StandInResolveManifest<'a> {
    fn from(manifest: &'a Value) -> Self {
        Self {
            manifest,
            cid: "unpacked",
        }
    }
}

impl<'a> From<(&'a Value, &'a str)> for StandInResolveManifest<'a> {
    fn from((manifest, cid): (&'a Value, &'a str)) -> Self {
        Self { manifest, cid }
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
/// Validate the passive photo profile and normalize its viewer to one capsule
/// requirement. `paths` is the planned or loaded listing, when available.
/// Before packing, the diagnostic identity is `unpacked`.
pub fn validate_content_stand_in(
    manifest: &Value,
    cid: &str,
    paths: &[&str],
) -> Result<Value, Refusal> {
    let invalid = |detail: String| Refusal::ContentBindingInvalid {
        cid: cid.to_string(),
        detail,
    };
    let fields = manifest
        .as_object()
        .ok_or_else(|| invalid("manifest must be an object".into()))?;
    if manifest["schema"] != "elastos.capsule/v1"
        || manifest["role"] != "content"
        || manifest["type"] != "data"
    {
        return Err(invalid(
            "schema, role and type must describe passive photo content".into(),
        ));
    }
    for field in fields.keys() {
        if !matches!(
            field.as_str(),
            "schema"
                | "name"
                | "version"
                | "description"
                | "role"
                | "type"
                | "entrypoint"
                | "viewer"
        ) {
            return Err(invalid(format!(
                "field {field} is outside the passive photo profile"
            )));
        }
    }
    let entrypoint = manifest["entrypoint"].as_str().unwrap_or_default();
    if entrypoint.rsplit_once('/').map(|(folder, _)| folder) != Some("images") {
        return Err(invalid(
            "entrypoint must name a regular file directly in images/".into(),
        ));
    }
    for path in std::iter::once(entrypoint)
        .chain(paths.iter().copied().filter(|path| *path != "capsule.json"))
    {
        stand_in_uri::check_object_uri(path, "images/")
            .map_err(|reason| invalid(format!("{path}: {reason}")))?;
    }
    let viewer = &manifest["viewer"];
    if viewer
        .as_object()
        .is_some_and(|fields| fields.keys().any(|field| field != "name" && field != "cid"))
    {
        return Err(invalid("viewer must have only name and cid".into()));
    }
    if viewer.is_string()
        || viewer.is_null()
        || viewer
            .as_object()
            .is_some_and(|fields| !fields.contains_key("cid"))
    {
        return Err(Refusal::ContentCoreUnpinned(cid.to_string()));
    }
    let viewer = viewer
        .as_object()
        .ok_or_else(|| invalid("viewer must be an object with only name and cid".into()))?;
    if viewer.len() != 2 || !viewer.contains_key("name") || !viewer.contains_key("cid") {
        return Err(invalid("viewer must have only name and cid".into()));
    }
    let name = viewer["name"]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invalid("viewer.name must be a nonempty string".into()))?;
    let viewer_cid = viewer["cid"]
        .as_str()
        .ok_or_else(|| invalid("viewer.cid must be a CID string".into()))?;
    check_cid_form(viewer_cid).map_err(|_| invalid("viewer.cid must be a CID string".into()))?;
    Ok(json!({ "name": name, "kind": "capsule", "cid": viewer_cid }))
}

/// The surface names its core by `requires[].cid` (review answer 7). A name
/// alone never selects a capsule.
pub fn resolve_requires<'a>(
    source: impl Into<StandInResolveManifest<'a>>,
    installed: &[Installed],
) -> Result<Vec<Installed>, Refusal> {
    let source = source.into();
    let manifest = source.manifest;
    // This test code stands in for the Runtime's launch by CID, which does not exist yet.
    let requires = if manifest["role"] == "content" {
        vec![validate_content_stand_in(manifest, source.cid, &[])?]
    } else {
        manifest
            .get("requires")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
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
    let copied = read_closure(staging)?.entries;
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
        // Its real path: on macOS the temporary folder is under a link.
        let base = root.path().canonicalize().unwrap();
        let source = base.join("source");
        let store = base.join("store");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("capsule.json"), b"{}").unwrap();
        std::fs::write(source.join("a.wasm"), b"verified").unwrap();
        let entries = read_closure(&source).unwrap().entries;
        let cid = cid_of(&entries);

        std::fs::write(source.join("a.wasm"), b"swapped!").unwrap();
        let refusal = stage(&source, &entries, &cid, &store).unwrap_err();
        assert_eq!(refusal.code(), "staged_mismatch", "{refusal}");
        assert!(!store.join(&cid).exists());
        let left: Vec<_> = std::fs::read_dir(&store).unwrap().collect();
        assert!(left.is_empty(), "the half-built copy is removed: {left:?}");
    }
}
