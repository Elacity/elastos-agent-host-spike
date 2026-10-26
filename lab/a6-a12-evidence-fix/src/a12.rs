//! A12 leftover census for Runtime-owned temp roots.
//!
//! Detection records the (dev, inode, birth/ctime, size+content hash) set
//! the run created. It does not depend on a name prefix or a lab marker.
//! Same-path delete+recreate with a reused inode is found. Real Runtime
//! leftovers have no lab marker; a rename to an unrelated name
//! (`moved-away`) must still be found.
//!
//! The census snapshot is taken before the Runtime starts. If the Runtime
//! already wrote, the snapshot fails. The run-window watch also covers
//! `$TMPDIR`, XDG cache/data/state/runtime dirs, and
//! `~/Library/Caches` / `~/Library/Application Support` (Mac).
//!
//! `ELASTOS_TMP_ROOT` is guarded: canonicalize (realpath) first. `/`, empty,
//! `$HOME`, a `..` component, a symlink anywhere at or under isolation, a
//! reachable live Home, and anything whose canonical path is not inside the
//! pack's fresh mktemp isolation are refused.
//! `ThrowawayHome` / `census::cleanup` are called for real; on Linux that
//! construction is NOT RUN.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
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

/// Identity of one path at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub birth_or_ctime: u128,
    pub size: u64,
    pub content_hash: u64,
}

/// Paths and file identities present under a watch root at one moment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsSnapshot {
    pub inodes: BTreeSet<(u64, u64)>,
    pub paths: BTreeSet<PathBuf>,
    pub ids: BTreeMap<PathBuf, FileId>,
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

fn path_has_parent_dir(path: &Path) -> bool {
    path.components()
        .any(|part| matches!(part, Component::ParentDir))
}

fn first_symlink_at_or_under(path: &Path, isolation: &Path) -> Option<PathBuf> {
    let mut acc = PathBuf::new();
    for part in path.components() {
        acc.push(part);
        if acc != isolation && !is_under(&acc, isolation) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) if meta.file_type().is_symlink() => return Some(acc),
            _ => {}
        }
    }
    None
}

fn realpath(path: &Path) -> Result<PathBuf, String> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|_| format!("ELASTOS_TMP_ROOT could not canonicalize {}", path.display()));
    }
    let mut acc = PathBuf::new();
    let mut last_existing = None;
    let mut rest = PathBuf::new();
    let mut seen_missing = false;
    for part in path.components() {
        if seen_missing {
            rest.push(part);
            continue;
        }
        acc.push(part);
        if acc.exists() {
            last_existing = Some(acc.clone());
        } else {
            seen_missing = true;
            rest.push(part);
        }
    }
    match last_existing {
        Some(prefix) => {
            let canon = fs::canonicalize(&prefix).map_err(|_| {
                format!(
                    "ELASTOS_TMP_ROOT could not canonicalize {}",
                    prefix.display()
                )
            })?;
            Ok(canon.join(rest))
        }
        None => Err(format!(
            "ELASTOS_TMP_ROOT could not canonicalize {}",
            path.display()
        )),
    }
}

fn canonical_isolation() -> Result<PathBuf, String> {
    realpath(&isolation_root())
}

fn live_home_reachable(canonical: &Path) -> Option<PathBuf> {
    for live in live_home_paths() {
        let live_canon = fs::canonicalize(&live).unwrap_or_else(|_| live.clone());
        if is_under(canonical, &live_canon) || is_under(&live_canon, canonical) {
            return Some(live);
        }
    }
    None
}

/// Refuse `/`, empty, `$HOME`, `..`, symlinks, live Homes, and anything
/// whose canonical path is outside the fresh mktemp isolation.
pub fn check_tmp_root(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("ELASTOS_TMP_ROOT is empty".into());
    }
    if !path.is_absolute() {
        return Err("ELASTOS_TMP_ROOT must be an absolute path under the pack mktemp".into());
    }
    if path_has_parent_dir(path) {
        return Err(format!(
            "ELASTOS_TMP_ROOT refuses '..' component in {}",
            path.display()
        ));
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
    if let Some(link) = first_symlink_at_or_under(path, &isolation) {
        return Err(format!(
            "ELASTOS_TMP_ROOT refuses symlink {} in {}",
            link.display(),
            path.display()
        ));
    }
    let canonical = realpath(path)?;
    if canonical == Path::new("/") {
        return Err("ELASTOS_TMP_ROOT refuses /".into());
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            if let Ok(home_canon) = fs::canonicalize(&home) {
                if canonical == home_canon {
                    return Err("ELASTOS_TMP_ROOT refuses $HOME".into());
                }
            }
        }
    }
    if let Some(live) = live_home_reachable(&canonical) {
        return Err(format!(
            "ELASTOS_TMP_ROOT refuses reachable live Home {}",
            live.display()
        ));
    }
    let isolation_canon = canonical_isolation()?;
    if !is_under(&canonical, &isolation_canon) {
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

const HASH_CAP: u64 = 64 * 1024;

#[cfg(unix)]
fn inode_of(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

#[cfg(not(unix))]
fn inode_of(_meta: &fs::Metadata) -> (u64, u64) {
    (0, 0)
}

fn file_len(meta: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        meta.size()
    }
    #[cfg(not(unix))]
    {
        meta.len()
    }
}

fn birth_or_ctime(meta: &fs::Metadata) -> u128 {
    if let Ok(created) = meta.created() {
        if let Ok(d) = created.duration_since(UNIX_EPOCH) {
            return d.as_nanos();
        }
    }
    #[cfg(unix)]
    {
        meta.ctime().max(0) as u128
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn content_hash(path: &Path, meta: &fs::Metadata, size: u64) -> u64 {
    if meta.file_type().is_symlink() || meta.is_dir() {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    if size <= HASH_CAP {
        if let Ok(bytes) = fs::read(path) {
            bytes.hash(&mut hasher);
            return hasher.finish();
        }
    }
    size.hash(&mut hasher);
    if let Ok(modified) = meta.modified() {
        if let Ok(d) = modified.duration_since(UNIX_EPOCH) {
            d.as_nanos().hash(&mut hasher);
        }
    }
    hasher.finish()
}

fn file_id(path: &Path, meta: &fs::Metadata) -> FileId {
    let (dev, ino) = inode_of(meta);
    let size = file_len(meta);
    FileId {
        dev,
        ino,
        birth_or_ctime: birth_or_ctime(meta),
        size,
        content_hash: content_hash(path, meta, size),
    }
}

fn has_any_files(root: &Path) -> bool {
    match fs::symlink_metadata(root) {
        Err(_) => false,
        Ok(meta) if meta.is_file() => true,
        Ok(meta) if meta.is_dir() => fs::read_dir(root)
            .map(|entries| entries.filter_map(|e| e.ok()).any(|_| true))
            .unwrap_or(false),
        Ok(_) => true,
    }
}

fn live_runtime_tmp_has_files() -> bool {
    has_any_files(&live_runtime_tmp_root())
}

fn runtime_wrote_under(watch: &Path) -> bool {
    has_any_files(&watch.join("storage")) || has_any_files(&watch.join("elastos"))
}

/// `$TMPDIR`, XDG cache/data/state/runtime, and Mac Library dirs.
pub fn extra_watch_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    let home = std::env::var("HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    for (var, fallback) in [
        ("XDG_CACHE_HOME", home.as_ref().map(|h| h.join(".cache"))),
        (
            "XDG_DATA_HOME",
            home.as_ref().map(|h| h.join(".local/share")),
        ),
        (
            "XDG_STATE_HOME",
            home.as_ref().map(|h| h.join(".local/state")),
        ),
        ("XDG_RUNTIME_DIR", None),
    ] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                roots.push(PathBuf::from(value));
                continue;
            }
        }
        if let Some(path) = fallback {
            roots.push(path);
        }
    }
    if let Some(h) = home {
        roots.push(h.join("Library/Caches"));
        roots.push(h.join("Library/Application Support"));
    }
    roots
}

/// Snapshot every path and identity under `watch` (missing watch is empty).
pub fn snapshot(watch: &Path) -> Result<FsSnapshot, String> {
    let mut snap = FsSnapshot::default();
    record_tree(watch, &mut snap, true, 0)?;
    Ok(snap)
}

/// Snapshot used for a Runtime leftover census. Fails if the Runtime already wrote.
pub fn snapshot_before_runtime(watch: &Path) -> Result<FsSnapshot, String> {
    if runtime_wrote_under(watch) || live_runtime_tmp_has_files() {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }
    snapshot(watch)
}

pub fn snapshot_run_window_unchecked() -> Result<FsSnapshot, String> {
    let mut snap = FsSnapshot::default();
    record_tree(&isolation_root(), &mut snap, true, 0)?;
    for root in extra_watch_roots() {
        if root.exists() {
            record_tree(&root, &mut snap, true, 0)?;
        }
    }
    Ok(snap)
}

/// Snapshot isolation plus extra watch roots, before the Runtime starts.
pub fn snapshot_run_window() -> Result<FsSnapshot, String> {
    if live_runtime_tmp_has_files() {
        return Err(
            "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
        );
    }
    if let Ok(tmp) = elastos_tmp_root() {
        if runtime_wrote_under(&tmp) {
            return Err(
                "snapshot must be taken before the Runtime starts; Runtime already wrote".into(),
            );
        }
    }
    snapshot_run_window_unchecked()
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
    snap.ids.insert(root.to_path_buf(), file_id(root, &meta));
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

/// True when `path` was created, moved, or recreated after `before`.
/// Identity is (dev, inode, birth/ctime, size+content hash).
fn keep_created_path(before: &FsSnapshot, path: &Path, id: &FileId) -> bool {
    match before.ids.get(path) {
        None => true,
        Some(old) => old != id,
    }
}

/// Leftovers keep an unrelated rename (`moved-away`). Plants may hide that.
fn allow_moved_away(path: &Path) -> bool {
    let _ = path;
    true
}

fn collect_created(before: &FsSnapshot, after: &FsSnapshot) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    for path in &after.paths {
        let meta = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(_) => return Err(format!("could not inspect {}", path.display())),
            Ok(meta) => meta,
        };
        let id = file_id(path, &meta);
        if keep_created_path(before, path, &id) && allow_moved_away(path) {
            found.insert(path.to_path_buf());
        }
    }
    Ok(found.into_iter().collect())
}

/// Leftovers created after `before` under `watch`, by identity, not marker.
pub fn leftovers_created(before: &FsSnapshot, watch: &Path) -> Result<Vec<PathBuf>, String> {
    let after = snapshot(watch)?;
    collect_created(before, &after)
}

/// Leftovers created in the run window across isolation and extra watch roots.
pub fn leftovers_in_run_window(before: &FsSnapshot) -> Result<Vec<PathBuf>, String> {
    let after = snapshot_run_window_unchecked()?;
    collect_created(before, &after)
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
