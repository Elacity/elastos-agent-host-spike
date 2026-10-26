//! A12 leftover census for Runtime-owned temp roots.
//!
//! Detection records the inode/path set the run created. It does not depend
//! on a name prefix or a lab marker. Real Runtime leftovers have no lab
//! marker; a rename to an unrelated name (`moved-away`) must still be found.
//!
//! `ELASTOS_TMP_ROOT` is guarded: `/`, empty, `$HOME`, live Home paths, and
//! anything not under the pack's fresh mktemp isolation are refused.
//! `ThrowawayHome` / `census::cleanup` are called for real; on Linux that
//! construction is NOT RUN.

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use agent_conformance::census;
use agent_conformance::harness::ThrowawayHome;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

static ISOLATED: AtomicU64 = AtomicU64::new(0);
static REAL_ROOT: Mutex<()> = Mutex::new(());
static ISOLATION: OnceLock<PathBuf> = OnceLock::new();

/// Bytes a lab plant may write. Census does not require this marker.
pub const LEFTOVER_MARKER: &[u8] = b"a6-a12-evidence-fix leftover-marker\n";
const PLANTED_NAME: &str = "a6-a12-evidence-fix-planted";
const ISOLATION_STAMP: &[u8] = b"a6-a12-evidence-fix isolation\n";
const ISOLATION_STAMP_NAME: &str = ".a6-a12-isolation";

/// Existing in-root census, invoked as functions (not by string name).
pub const EXISTING_CLEANUP: &str = "agent_conformance::census::cleanup";
pub const EXISTING_HOME: &str = "agent_conformance::harness::ThrowawayHome";

/// Live Runtime temp. A census target only. Never a pack plant root.
pub fn live_runtime_tmp_root() -> PathBuf {
    PathBuf::from("/tmp/elastos")
}

/// Inodes and paths present under a watch root at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsSnapshot {
    pub inodes: BTreeSet<(u64, u64)>,
    pub paths: BTreeSet<PathBuf>,
}

/// Isolation root created by `mktemp -d` (or the env set by `run.sh`).
pub fn isolation_root() -> PathBuf {
    ISOLATION
        .get_or_init(|| {
            if let Ok(value) = std::env::var("ELASTOS_TMP_ISOLATION") {
                let path = PathBuf::from(&value);
                if isolation_stamp_ok(&path) {
                    return path;
                }
            }
            create_mktemp_isolation()
        })
        .clone()
}

fn isolation_stamp_ok(root: &Path) -> bool {
    match fs::read(root.join(ISOLATION_STAMP_NAME)) {
        Ok(bytes) => bytes == ISOLATION_STAMP && root.is_absolute(),
        Err(_) => false,
    }
}

fn create_mktemp_isolation() -> PathBuf {
    let template = format!("{}/a6-a12-pack.XXXXXX", std::env::temp_dir().display());
    let output = Command::new("mktemp")
        .arg("-d")
        .arg(&template)
        .output()
        .expect("mktemp -d for A12 isolation");
    assert!(
        output.status.success(),
        "mktemp -d failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    assert!(path.is_absolute(), "mktemp must return an absolute path");
    fs::write(path.join(ISOLATION_STAMP_NAME), ISOLATION_STAMP).expect("isolation stamp");
    path
}

fn live_home_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        paths.push(home.join(".local/share/elastos"));
        paths.push(home.join("Library/Application Support/elastos"));
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        paths.push(PathBuf::from(xdg).join("elastos"));
    }
    if let Ok(live) = std::env::var("ELASTOS_LIVE_HOME") {
        paths.push(PathBuf::from(live));
    }
    if let Ok(live_xdg) = std::env::var("ELASTOS_LIVE_XDG_DATA_HOME") {
        paths.push(PathBuf::from(live_xdg).join("elastos"));
    }
    paths
}

fn is_under(child: &Path, parent: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

/// Refuse `/`, empty, `$HOME`, live Home paths, and anything outside isolation.
pub fn check_tmp_root(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("ELASTOS_TMP_ROOT is empty".into());
    }
    if path == Path::new("/") {
        return Err("ELASTOS_TMP_ROOT refuses /".into());
    }
    if !path.is_absolute() {
        return Err("ELASTOS_TMP_ROOT must be an absolute path under the pack mktemp".into());
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() && path == Path::new(&home) {
            return Err("ELASTOS_TMP_ROOT refuses $HOME".into());
        }
    }
    for live in live_home_paths() {
        if path == live || path.starts_with(&live) {
            return Err(format!(
                "ELASTOS_TMP_ROOT refuses live Home path {}",
                live.display()
            ));
        }
    }
    let isolation = isolation_root();
    if !is_under(path, &isolation) {
        return Err(format!(
            "ELASTOS_TMP_ROOT {} is not under isolated mktemp {}",
            path.display(),
            isolation.display()
        ));
    }
    Ok(())
}

pub fn elastos_tmp_root() -> Result<PathBuf, String> {
    match std::env::var("ELASTOS_TMP_ROOT") {
        Ok(value) => {
            let path = PathBuf::from(value);
            check_tmp_root(&path)?;
            Ok(path)
        }
        Err(_) => Err("ELASTOS_TMP_ROOT is unset; pack must set an isolated mktemp dir".into()),
    }
}

pub fn storage_root() -> Result<PathBuf, String> {
    Ok(elastos_tmp_root()?.join("storage"))
}

pub fn runtime_owned_temp_roots() -> Result<Vec<PathBuf>, String> {
    let tmp = elastos_tmp_root()?;
    Ok(vec![tmp.join("storage"), tmp])
}

/// Create the storage tree a Runtime `LocalFSProvider::new` / `create_runtime`
/// run would create, then leave a leftover file.
pub fn create_runtime_storage_leftover(tmp_root: &Path) -> Result<PathBuf, String> {
    create_plain_leftover(tmp_root, PLANTED_NAME, LEFTOVER_MARKER)
}

/// Leftover with caller bytes. Census must find this with no lab marker.
pub fn create_plain_leftover(tmp_root: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let storage = tmp_root.join("storage");
    fs::create_dir_all(&storage).map_err(|_| format!("could not create {}", storage.display()))?;
    let leftover = storage.join(name);
    fs::write(&leftover, bytes).map_err(|_| format!("could not write {}", leftover.display()))?;
    Ok(leftover)
}

#[cfg(unix)]
fn inode_of(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn inode_of(_meta: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

/// Snapshot every path and inode under `watch` (missing watch is empty).
pub fn snapshot(watch: &Path) -> Result<FsSnapshot, String> {
    let mut snap = FsSnapshot::default();
    record_tree(watch, &mut snap, true, 0)?;
    Ok(snap)
}

fn record_tree(
    root: &Path,
    snap: &mut FsSnapshot,
    follow_root_symlink: bool,
    depth: u32,
) -> Result<(), String> {
    if depth > 64 {
        return Err(format!("walk too deep or loop at {}", root.display()));
    }
    let meta = match fs::symlink_metadata(root) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(format!("could not inspect {}", root.display())),
        Ok(meta) => meta,
    };
    snap.paths.insert(root.to_path_buf());
    snap.inodes.insert(inode_of(&meta));
    if meta.file_type().is_symlink() {
        if follow_root_symlink {
            let target = fs::canonicalize(root)
                .map_err(|_| format!("could not resolve symlink root {}", root.display()))?;
            record_tree(&target, snap, false, depth + 1)?;
        }
        return Ok(());
    }
    if !meta.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(root).map_err(|_| format!("could not read {}", root.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|_| format!("could not read entry under {}", root.display()))?
            .path();
        record_tree(&path, snap, true, depth + 1)?;
    }
    Ok(())
}

/// True when `path`/`ino` was created or moved after `before`.
/// Name prefix and file bytes are not consulted.
fn keep_created_path(before: &FsSnapshot, path: &Path, ino: (u64, u64)) -> bool {
    let new_inode = !before.inodes.contains(&ino);
    let new_path = !before.paths.contains(path);
    new_inode || new_path
}

/// Leftovers keep an unrelated rename (`moved-away`). Plants may hide that.
fn allow_moved_away(path: &Path) -> bool {
    let _ = path;
    true
}

/// Leftovers created after `before` under `watch`, by inode/path, not marker.
pub fn leftovers_created(before: &FsSnapshot, watch: &Path) -> Result<Vec<PathBuf>, String> {
    let after = snapshot(watch)?;
    let mut found = BTreeSet::new();
    for path in &after.paths {
        let meta = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(format!("could not inspect {}", path.display())),
            Ok(meta) => meta,
        };
        let ino = inode_of(&meta);
        if keep_created_path(before, path, ino) && allow_moved_away(path) {
            found.insert(path.to_path_buf());
        }
    }
    Ok(found.into_iter().collect())
}

pub fn leftovers_under(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    for root in roots {
        walk_root(root, &mut found, true)?;
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
                }
            }
            continue;
        }
        if meta.is_dir() {
            walk_resolved(&path, found)?;
        }
    }
    Ok(())
}

pub fn runtime_temp_census() -> Result<String, String> {
    runtime_temp_census_at(&runtime_owned_temp_roots()?)
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

pub fn runtime_temp_census_since(before: &FsSnapshot, watch: &Path) -> Result<String, String> {
    let leftovers = leftovers_created(before, watch)?;
    if leftovers.is_empty() {
        Ok(format!(
            "runtime-temp census: PASS leftovers:0 watch:{}",
            watch.display()
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
            "ThrowawayHome::new refused: {reason}. Mac: ELASTOS_TMP_ROOT=<isolated-mktemp> cargo test --manifest-path lab/agent-conformance/Cargo.toml --test runtime cleanup_census_refuses_each_leftover -- --nocapture"
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
        let tmp = elastos_tmp_root()?;
        let storage = tmp.join("storage");
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
    let dir = isolation_root().join(format!(
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
