//! Corrected A12 cleanup census: include Runtime-owned temp roots.
//!
//! The agent-conformance census (`census::cleanup`) inspects the throwaway
//! root, its TMPDIR, and the API port, then labels outside-root leftovers
//! `BLOCKED(AC-006-STORAGE)` without walking `/tmp/elastos/storage`. This
//! crate invokes that module by source (`existing.rs`) and name; it does not
//! compile the owner crate (that graph pulls Runtime).

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

static ISOLATED: AtomicU64 = AtomicU64::new(0);
static REAL_ROOT: Mutex<()> = Mutex::new(());

/// Production paths the Runtime creates outside a throwaway Home.
/// `/tmp/elastos/storage` is the `create_runtime` / `serve --storage-path`
/// default. `/tmp/elastos` is the `security_cmd` data-dir fallback parent
/// and covers `policy.json` and `crosvm-empty` under the same tree.
pub const RUNTIME_TEMP_ROOTS: &[&str] = &["/tmp/elastos/storage", "/tmp/elastos"];

/// Existing in-root census, invoked by name (see `existing.rs`).
pub const EXISTING_CLEANUP: &str = "agent_conformance::census::cleanup";
pub const EXISTING_HOME: &str = "agent_conformance::harness::ThrowawayHome";

const PLANTED_NAME: &str = "a6-a12-evidence-fix-planted";

pub fn runtime_owned_temp_roots() -> Vec<PathBuf> {
    RUNTIME_TEMP_ROOTS.iter().map(PathBuf::from).collect()
}

pub fn leftovers_under(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    for root in roots {
        walk_root(root, &mut found)?;
    }
    Ok(found.into_iter().collect())
}

fn walk_root(root: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let meta = match fs::symlink_metadata(root) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(format!("could not inspect {}", root.display())),
        Ok(meta) => meta,
    };
    found.insert(root.to_path_buf());
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(root).map_err(|_| format!("could not read {}", root.display()))?;
    for entry in entries {
        let entry = entry.map_err(|_| format!("could not read entry under {}", root.display()))?;
        walk_root(&entry.path(), found)?;
    }
    Ok(())
}

pub fn runtime_temp_census() -> Result<String, String> {
    runtime_temp_census_at(&runtime_owned_temp_roots())
}

pub fn runtime_temp_census_at(roots: &[PathBuf]) -> Result<String, String> {
    let leftovers = leftovers_under(roots)?;
    if leftovers.is_empty() {
        Ok(format!(
            "runtime-temp census: PASS leftovers:0 roots:{roots:?}"
        ))
    } else {
        Err(format!(
            "runtime-temp census: FAIL leftovers:{} paths:{leftovers:?}",
            leftovers.len()
        ))
    }
}

#[derive(Debug)]
pub enum HostPart {
    Pass(String),
    Fail(String),
    NotRun(String),
}

/// Invoke the existing throwaway-Home census when this host can run it.
/// Linux matches `ThrowawayHome::data_dir` (`harness.rs`): Homes need macOS.
pub fn in_root_census_on_this_host() -> HostPart {
    if !cfg!(target_os = "macos") {
        return HostPart::NotRun(format!(
            "in-root A12 census via {EXISTING_CLEANUP}: throwaway Homes require macOS; A6/A12 resident instances are out of scope"
        ));
    }
    HostPart::NotRun(format!(
        "in-root A12 census via {EXISTING_HOME}: resident instances are out of scope on this task"
    ))
}

pub fn merge_host(in_root: HostPart, temps: Result<String, String>) -> Result<String, String> {
    match (in_root, temps) {
        (HostPart::Pass(left), Ok(right)) | (HostPart::NotRun(left), Ok(right)) => {
            Ok(format!("{left}; {right}"))
        }
        (HostPart::Pass(left), Err(right))
        | (HostPart::NotRun(left), Err(right))
        | (HostPart::Fail(left), Ok(right))
        | (HostPart::Fail(left), Err(right)) => Err(format!("{left}; {right}")),
    }
}

/// Merge an existing `census::cleanup` result with the Runtime temp walk.
pub fn cleanup_with_runtime_temps(
    existing_cleanup: Result<String, String>,
) -> Result<String, String> {
    merge_host(
        match existing_cleanup {
            Ok(text) => HostPart::Pass(text),
            Err(text) => HostPart::Fail(text),
        },
        runtime_temp_census(),
    )
}

/// Plant a file at the real Runtime storage root. Drop restores only what
/// this plant created.
pub struct StoragePlant {
    path: PathBuf,
    created: Vec<PathBuf>,
    _lock: MutexGuard<'static, ()>,
}

impl StoragePlant {
    pub fn place() -> Result<Self, String> {
        let lock = REAL_ROOT
            .lock()
            .map_err(|_| "Runtime storage plant lock is poisoned")?;
        let path = PathBuf::from("/tmp/elastos/storage").join(PLANTED_NAME);
        let mut created = Vec::new();
        for dir in [
            PathBuf::from("/tmp/elastos"),
            PathBuf::from("/tmp/elastos/storage"),
        ] {
            match fs::symlink_metadata(&dir) {
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    fs::create_dir(&dir)
                        .map_err(|_| format!("could not create {}", dir.display()))?;
                    created.push(dir);
                }
                Err(_) => return Err(format!("could not inspect {}", dir.display())),
                Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                    return Err(format!("{} is not a directory", dir.display()));
                }
                Ok(_) => {}
            }
        }
        fs::write(&path, b"a12 planted leftover\n")
            .map_err(|_| format!("could not plant {}", path.display()))?;
        Ok(Self {
            path,
            created,
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StoragePlant {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        for dir in self.created.iter().rev() {
            let _ = fs::remove_dir(dir);
        }
    }
}

pub fn isolated_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("a12-isolated")
        .join(format!(
            "{}-{}-{}-{}",
            label,
            std::process::id(),
            stamp,
            ISOLATED.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&dir).expect("isolated A12 root");
    dir
}

pub fn remove_isolated(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}
