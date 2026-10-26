//! A12 leftover census for Runtime-owned temp roots.
//!
//! Roots honour `ELASTOS_TMP_ROOT` (default `/tmp/elastos` when unset). A
//! leftover is found by walking resolved roots and by a leftover marker, not
//! by a fixed directory name. `ThrowawayHome` / `census::cleanup` are called
//! for real; on Linux that construction is NOT RUN.

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_conformance::census;
use agent_conformance::harness::ThrowawayHome;

static ISOLATED: AtomicU64 = AtomicU64::new(0);
static REAL_ROOT: Mutex<()> = Mutex::new(());

/// Bytes written by a run leftover. Detection searches for this marker.
pub const LEFTOVER_MARKER: &[u8] = b"a6-a12-evidence-fix leftover-marker\n";
const PLANTED_NAME: &str = "a6-a12-evidence-fix-planted";

/// Existing in-root census, invoked as functions (not by string name).
pub const EXISTING_CLEANUP: &str = "agent_conformance::census::cleanup";
pub const EXISTING_HOME: &str = "agent_conformance::harness::ThrowawayHome";

/// Shared default when `ELASTOS_TMP_ROOT` is unset. The Mac pack sets the env.
pub fn default_tmp_root() -> PathBuf {
    PathBuf::from("/tmp/elastos")
}

pub fn elastos_tmp_root() -> PathBuf {
    match std::env::var("ELASTOS_TMP_ROOT") {
        Ok(value) if !value.is_empty() => PathBuf::from(value),
        _ => default_tmp_root(),
    }
}

pub fn storage_root() -> PathBuf {
    elastos_tmp_root().join("storage")
}

pub fn runtime_owned_temp_roots() -> Vec<PathBuf> {
    vec![storage_root(), elastos_tmp_root()]
}

/// Create the storage tree a Runtime `LocalFSProvider::new` / `create_runtime`
/// run would create, then leave a marker leftover.
pub fn create_runtime_storage_leftover(tmp_root: &Path) -> Result<PathBuf, String> {
    let storage = tmp_root.join("storage");
    fs::create_dir_all(&storage).map_err(|_| format!("could not create {}", storage.display()))?;
    let leftover = storage.join(PLANTED_NAME);
    fs::write(&leftover, LEFTOVER_MARKER)
        .map_err(|_| format!("could not write {}", leftover.display()))?;
    Ok(leftover)
}

pub fn leftovers_under(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    for root in roots {
        walk_root(root, &mut found, true)?;
        scan_parent_for_marker(root, &mut found)?;
    }
    Ok(found.into_iter().collect())
}

fn walk_root(
    root: &Path,
    found: &mut BTreeSet<PathBuf>,
    follow_root_symlink: bool,
) -> Result<(), String> {
    let meta = match fs::symlink_metadata(root) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(());
        }
        Err(_) => return Err(format!("could not inspect {}", root.display())),
        Ok(meta) => meta,
    };
    found.insert(root.to_path_buf());
    if meta.file_type().is_symlink() {
        if follow_root_symlink {
            let target = fs::canonicalize(root)
                .map_err(|_| format!("could not resolve symlink root {}", root.display()))?;
            found.insert(target.clone());
            walk_resolved(&target, found)?;
        }
        return Ok(());
    }
    if !meta.is_dir() {
        record_if_marker(root, found)?;
        return Ok(());
    }
    walk_resolved(root, found)
}

fn walk_resolved(dir: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|_| format!("could not read {}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|_| format!("could not read entry under {}", dir.display()))?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| format!("could not inspect {}", path.display()))?;
        found.insert(path.clone());
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::canonicalize(&path) {
                found.insert(target.clone());
                if target.is_dir() {
                    walk_resolved(&target, found)?;
                } else {
                    record_if_marker(&target, found)?;
                }
            }
            continue;
        }
        if meta.is_dir() {
            walk_resolved(&path, found)?;
        } else {
            record_if_marker(&path, found)?;
        }
    }
    Ok(())
}

fn record_if_marker(path: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    match fs::read(path) {
        Ok(bytes) if bytes == LEFTOVER_MARKER => {
            found.insert(path.to_path_buf());
            Ok(())
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

/// Renamed leftover trees keep the marker. Scan sibling names, not the old path.
fn scan_parent_for_marker(root: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let Some(name) = root.file_name() else {
        return Ok(());
    };
    let Some(parent) = root.parent() else {
        return Ok(());
    };
    if !parent.is_dir() {
        return Ok(());
    }
    let prefix = name.to_string_lossy();
    let entries = match fs::read_dir(parent) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(format!("could not scan {}", parent.display())),
        Ok(entries) => entries,
    };
    for entry in entries {
        let path = entry
            .map_err(|_| format!("could not read {}", parent.display()))?
            .path();
        if path == root {
            continue;
        }
        let file_name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let Some(file_name) = file_name else {
            continue;
        };
        if !file_name.starts_with(prefix.as_ref()) {
            continue;
        }
        scan_tree_for_marker(&path, found)?;
    }
    Ok(())
}

fn scan_tree_for_marker(dir: &Path, found: &mut BTreeSet<PathBuf>) -> Result<(), String> {
    let entries = match fs::read_dir(dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(format!("could not scan {}", dir.display())),
        Ok(entries) => entries,
    };
    for entry in entries {
        let path = entry
            .map_err(|_| format!("could not read {}", dir.display()))?
            .path();
        let meta = match fs::symlink_metadata(&path) {
            Err(_) => continue,
            Ok(meta) => meta,
        };
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::canonicalize(&path) {
                if target.is_dir() {
                    scan_tree_for_marker(&target, found)?;
                } else {
                    record_if_marker(&target, found)?;
                }
            }
        } else if meta.is_dir() {
            scan_tree_for_marker(&path, found)?;
        } else {
            record_if_marker(&path, found)?;
        }
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

/// Call the owner `ThrowawayHome` + `census::cleanup` path.
/// Linux cannot build a throwaway Home (`harness.rs` data_dir).
pub fn in_root_census_on_this_host() -> HostPart {
    match ThrowawayHome::new() {
        Err(reason) if reason.contains("macOS") => HostPart::NotRun(format!(
            "ThrowawayHome::new refused: {reason}. Mac: cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --nocapture"
        )),
        Err(reason) => HostPart::Fail(format!("ThrowawayHome::new: {reason}")),
        Ok(home) => match census::cleanup(&home, 1) {
            Ok(line) => {
                let _ = home.finish();
                HostPart::Pass(format!("{EXISTING_CLEANUP}: {line}"))
            }
            Err(line) => HostPart::Fail(format!("{EXISTING_CLEANUP}: {line}")),
        },
    }
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

/// Hold the process lock, set `ELASTOS_TMP_ROOT`, run `f`, then restore.
pub fn with_tmp_root<T>(root: &Path, f: impl FnOnce() -> T) -> T {
    let _lock = lock_real_root();
    let previous = std::env::var_os("ELASTOS_TMP_ROOT");
    std::env::set_var("ELASTOS_TMP_ROOT", root);
    let result = f();
    match previous {
        Some(value) => std::env::set_var("ELASTOS_TMP_ROOT", value),
        None => std::env::remove_var("ELASTOS_TMP_ROOT"),
    }
    result
}

/// Plant a leftover under the current `ELASTOS_TMP_ROOT` storage path.
/// Callers that change the env must already hold `with_tmp_root`.
pub struct StoragePlant {
    path: PathBuf,
    created: Vec<PathBuf>,
}

impl StoragePlant {
    pub fn place() -> Result<Self, String> {
        let tmp = elastos_tmp_root();
        let storage = storage_root();
        let path = storage.join(PLANTED_NAME);
        let mut created = Vec::new();
        for dir in [tmp, storage] {
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
        fs::write(&path, LEFTOVER_MARKER)
            .map_err(|_| format!("could not plant {}", path.display()))?;
        Ok(Self { path, created })
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

pub fn lock_real_root() -> MutexGuard<'static, ()> {
    REAL_ROOT.lock().expect("Runtime storage plant lock")
}
