//! One successful installed release verification for Browser catalogue reads.
//! Real starts use `verify_installed_component_start` and always verify again.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use elastos_common::localhost::{
    installation_release_head_path, installation_release_manifest_path,
    publisher_release_head_path, publisher_release_manifest_path,
};

use crate::sources::TrustedSource;

#[derive(Clone, PartialEq, Eq)]
struct FileState {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    nlink: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

impl From<fs::Metadata> for FileState {
    fn from(meta: fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mode: meta.mode(),
            uid: meta.uid(),
            nlink: meta.nlink(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct ReleaseKey {
    data: PathBuf,
    runtime: PathBuf,
    inputs: Vec<(PathBuf, Option<FileState>)>,
}

struct VerifiedRelease {
    key: ReleaseKey,
    components: Vec<u8>,
}

static VERIFIED: OnceLock<Mutex<Option<VerifiedRelease>>> = OnceLock::new();

fn file_state(path: &Path) -> Option<Option<FileState>> {
    match fs::symlink_metadata(path) {
        // A reader can follow sources.json through a link. The link's own
        // metadata cannot describe changes to its target, so do not cache it.
        Ok(meta) if meta.file_type().is_symlink() => None,
        Ok(meta) => Some(Some(meta.into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None, // Unreadable inputs always take the full verifier path.
    }
}

fn key(data: &Path, runtime: &Path, source: &TrustedSource) -> Option<ReleaseKey> {
    if crate::install_transaction::InstallTransaction::has_pending_recovery(runtime) {
        return None;
    }
    let publisher_head = publisher_release_head_path(data);
    let publisher_release = publisher_release_manifest_path(data);
    let installed_head = installation_release_head_path(data);
    let installed_release = installation_release_manifest_path(data);
    let paths = [
        data.to_path_buf(),
        data.join("components.json"),
        data.join("sources.json"),
        data.join("installation"),
        data.join(".elastos.installation-migrate"),
        runtime.to_path_buf(),
        PathBuf::from(&source.install_path),
        runtime.parent()?.to_path_buf(),
        publisher_head.parent()?.to_path_buf(),
        publisher_head,
        publisher_release,
        installed_head,
        installed_release,
    ];
    let mut paths = paths.into_iter().collect::<BTreeSet<_>>();
    // The signed-input reader checks each directory below the data root. A
    // changed parent permission or a replaced intermediate directory also
    // makes the cached result stale.
    for parent in [
        publisher_release_head_path(data),
        installation_release_head_path(data),
    ] {
        let mut current = parent.parent()?;
        while current.starts_with(data) {
            paths.insert(current.to_path_buf());
            if current == data {
                break;
            }
            current = current.parent()?;
        }
    }
    let inputs = paths
        .into_iter()
        .map(|path| Some((path.clone(), file_state(&path)?)))
        .collect::<Option<Vec<_>>>()?;
    Some(ReleaseKey {
        data: data.to_path_buf(),
        runtime: runtime.to_path_buf(),
        inputs,
    })
}

pub(super) fn verified_components(
    data: &Path,
    runtime: &Path,
    source: &TrustedSource,
) -> anyhow::Result<Vec<u8>> {
    let before = key(data, runtime, source);
    if let Some(ref key) = before {
        if let Ok(guard) = VERIFIED.get_or_init(Default::default).lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.key == *key {
                    return Ok(cached.components.clone());
                }
            }
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    count_verification(data);
    let (_, components) =
        crate::installed_release::read_signed_release(data, runtime, source, false, true)?;
    let after = key(data, runtime, source);
    if before.is_some() && before == after {
        if let Ok(mut guard) = VERIFIED.get_or_init(Default::default).lock() {
            *guard = Some(VerifiedRelease {
                key: after.unwrap(),
                components: components.clone(),
            });
        }
    }
    Ok(components)
}

#[cfg(all(test, target_os = "macos"))]
static VERIFICATIONS: OnceLock<Mutex<std::collections::HashMap<PathBuf, usize>>> = OnceLock::new();

#[cfg(all(test, target_os = "macos"))]
fn count_verification(data: &Path) {
    if let Ok(mut counts) = VERIFICATIONS.get_or_init(Default::default).lock() {
        *counts.entry(data.to_path_buf()).or_default() += 1;
    }
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn verification_count(data: &Path) -> usize {
    VERIFICATIONS
        .get_or_init(Default::default)
        .lock()
        .ok()
        .and_then(|counts| counts.get(data).copied())
        .unwrap_or_default()
}
