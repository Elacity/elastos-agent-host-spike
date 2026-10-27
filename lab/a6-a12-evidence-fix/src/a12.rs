//! A12 leftover census for Runtime-owned temp roots.
//!
//! Detection records the (dev, inode, ctime, size+full-content hash,
//! file handle) set the run created. It does not depend on a name prefix, a lab marker,
//! birth time, or size+mtime. Same-path delete+recreate with a reused
//! inode and the same bytes is found. An in-place rewrite of a file
//! larger than 64 KiB with mtime restored is found (the named test
//! changes the last byte, so a 64 KiB hash cap is refused). The content
//! hash covers the whole file and is sparse-aware: a SEEK_HOLE map is
//! mixed into the digest so a hole is not the same as written zeros.
//! `name_to_handle_at` must return a non-empty handle; an empty handle
//! is FileId NOT RUN, not a weaker identity. Real Runtime leftovers
//! have no lab marker; a rename to an unrelated name (`moved-away`) must
//! still be found.
//!
//! The census snapshot is taken before the Runtime starts. If the Runtime
//! already wrote, the snapshot fails. The run-window watch snapshots
//! isolation plus every writable temp root (`/tmp`, `/var/tmp`, `/dev/shm`,
//! `$TMPDIR`), XDG cache/data/state/runtime dirs, `$HOME/.cache` even when
//! `XDG_CACHE_HOME` is set, `/run/user/$UID` when that dir exists, and
//! `~/Library/Caches` / `~/Library/Application Support` (Mac). Live watches
//! recurse into those trees. `watch.add` failures fail closed. An inotify
//! watch records create-then-delete, including in a subdirectory. Vanished
//! inodes are followed by file handle / `(dev,ino)` so a hardlink or rename
//! out of the watch still lists the dest leftover. Bind mount, pid
//! namespace, `/run/user/$UID` when absent, watch sysctl write, and a
//! setsid write after the census returns are HostPart::NotRun, never a
//! clean-window PASS.
//!
//! `ELASTOS_TMP_ROOT` is guarded: canonicalize (realpath) first. `/`, empty,
//! `$HOME`, a `..` component, a symlink anywhere at or under isolation, a
//! reachable live Home, and anything whose canonical path is not inside the
//! pack's fresh mktemp isolation are refused. Writes re-check the root,
//! then open from the isolation dirfd with `openat2(RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS)`, so a parent or leaf symlink swap cannot land a
//! leftover outside isolation.
//! `ThrowawayHome` / `census::cleanup` are called for real; on Linux that
//! construction is NOT RUN.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{ErrorKind, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
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
static LIVE_WATCH: Mutex<Option<LiveWatch>> = Mutex::new(None);

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
///
/// Time is inode ctime (nsec), not birth time. Large files hash full
/// content with no 64 KiB cap, not size+mtime. The digest includes a
/// SEEK_HOLE map so a hole is not the same as written zeros.
/// `file_handle` is the `name_to_handle_at` cookie (inode generation).
/// An empty handle is FileId NOT RUN, not a weaker identity. On this
/// ext4 host, unlink+recreate can reuse inode+dev+ctime with the same
/// bytes; the handle still moves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub ctime: i64,
    pub size: u64,
    pub content_hash: u64,
    pub file_handle: Vec<u8>,
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
/// Re-checks the root, then writes through isolation-relative
/// `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.
pub fn create_plain_leftover(tmp_root: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    write_isolated_leftover(tmp_root, "storage", name, bytes)
}

fn refused_name(name: &str) -> bool {
    name.is_empty()
        || name.contains('/')
        || name.contains('\0')
        || name == "."
        || name == ".."
        || name.contains('\\')
}

fn open_or_create_dir_nofollow(path: &Path) -> Result<fs::File, String> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC);
    match opts.open(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|create_err| {
                format!("could not create {}: {create_err}", path.display())
            })?;
            opts.open(path).map_err(|open_err| {
                format!(
                    "ELASTOS_TMP_ROOT write refuses {} after create: {open_err}",
                    path.display()
                )
            })
        }
        Err(error) => Err(format!(
            "ELASTOS_TMP_ROOT write refuses {}: {error}",
            path.display()
        )),
    }
}

#[allow(dead_code)]
fn mkdirat_open(parent: &fs::File, name: &str) -> Result<fs::File, String> {
    if refused_name(name) {
        return Err(format!("refused directory name {name:?}"));
    }
    let c_name = CString::new(name).map_err(|_| format!("refused directory name {name:?}"))?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o755) };
    if created != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != ErrorKind::AlreadyExists {
            return Err(format!("could not mkdirat {name}: {err}"));
        }
    }
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "ELASTOS_TMP_ROOT write refuses {name}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn writeat(dir: &fs::File, name: &str, bytes: &[u8]) -> Result<(), String> {
    if refused_name(name) {
        return Err(format!("refused file name {name:?}"));
    }
    let c_name = CString::new(name).map_err(|_| format!("refused file name {name:?}"))?;
    let fd = openat2_beneath(
        dir.as_raw_fd(),
        &c_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
        0o644,
    )?;
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    file.write_all(bytes)
        .map_err(|error| format!("could not write {name}: {error}"))
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const SYS_OPENAT2: libc::c_long = 437;

fn openat2_beneath(dirfd: i32, name: &CString, flags: i32, mode: u32) -> Result<i32, String> {
    let how = OpenHow {
        flags: flags as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS,
    };
    let fd = unsafe {
        libc::syscall(
            SYS_OPENAT2,
            dirfd,
            name.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(format!(
            "ELASTOS_TMP_ROOT write refuses {}: {}",
            String::from_utf8_lossy(name.as_bytes()),
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd as i32)
}

fn mkdirat_openat2(parent: &fs::File, name: &str) -> Result<fs::File, String> {
    if refused_name(name) {
        return Err(format!("refused directory name {name:?}"));
    }
    let c_name = CString::new(name).map_err(|_| format!("refused directory name {name:?}"))?;
    let created = unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o755) };
    if created != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != ErrorKind::AlreadyExists {
            return Err(format!("could not mkdirat {name}: {err}"));
        }
    }
    let fd = openat2_beneath(
        parent.as_raw_fd(),
        &c_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )?;
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn open_rel_beneath(isolation: &fs::File, rel: &Path) -> Result<fs::File, String> {
    let mut fd = isolation
        .try_clone()
        .map_err(|error| format!("could not clone isolation fd: {error}"))?;
    for part in rel.components() {
        let name = match part {
            Component::Normal(name) => name,
            Component::CurDir => continue,
            _ => {
                return Err(format!(
                    "ELASTOS_TMP_ROOT write refuses relative component {part:?}"
                ));
            }
        };
        let name = name
            .to_str()
            .ok_or_else(|| format!("ELASTOS_TMP_ROOT write refuses non-utf8 {name:?}"))?;
        fd = mkdirat_openat2(&fd, name)?;
    }
    Ok(fd)
}

/// Re-check the root, then write through isolation-relative `openat2`.
pub fn write_isolated_leftover(
    tmp_root: &Path,
    dir_name: &str,
    name: &str,
    bytes: &[u8],
) -> Result<PathBuf, String> {
    check_tmp_root(tmp_root)?;
    let isolation = isolation_root();
    let iso_fd = open_or_create_dir_nofollow(&isolation)?;
    let rel = tmp_root.strip_prefix(&isolation).map_err(|_| {
        format!(
            "ELASTOS_TMP_ROOT write refuses {}: not under isolation {}",
            tmp_root.display(),
            isolation.display()
        )
    })?;
    let root_fd = open_rel_beneath(&iso_fd, rel)?;
    let dir_fd = mkdirat_openat2(&root_fd, dir_name)?;
    writeat(&dir_fd, name, bytes)?;
    Ok(tmp_root.join(dir_name).join(name))
}

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

fn inode_ctime(meta: &fs::Metadata) -> i64 {
    #[cfg(unix)]
    {
        meta.ctime()
            .saturating_mul(1_000_000_000)
            .saturating_add(meta.ctime_nsec())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

fn content_hash(path: &Path, meta: &fs::Metadata) -> u64 {
    if meta.file_type().is_symlink() || meta.is_dir() {
        return 0;
    }
    let mut hasher = DefaultHasher::new();
    hash_whole_file_sparse(path, meta, &mut hasher);
    hasher.finish()
}

/// Whole-file digest. No 64 KiB cap. A SEEK_HOLE / SEEK_DATA map is
/// mixed in so a hole is not the same as written zeros.
fn hash_whole_file_sparse(path: &Path, meta: &fs::Metadata, hasher: &mut DefaultHasher) {
    let Ok(file) = fs::File::open(path) else {
        return;
    };
    let fd = file.as_raw_fd();
    let size = file_len(meta) as i64;
    size.hash(hasher);
    let mut pos: i64 = 0;
    while pos < size {
        let data = unsafe { libc::lseek(fd, pos, libc::SEEK_DATA) };
        if data < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENXIO) {
                b"HOLE".hash(hasher);
                (size - pos).hash(hasher);
            }
            break;
        }
        if data > pos {
            b"HOLE".hash(hasher);
            (data - pos).hash(hasher);
        }
        if data >= size {
            break;
        }
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            break;
        }
        let end = hole.min(size);
        b"DATA".hash(hasher);
        (end - data).hash(hasher);
        hash_extent_bytes(fd, data, end, hasher);
        if end <= pos {
            break;
        }
        pos = end;
    }
}

fn hash_extent_bytes(fd: i32, start: i64, end: i64, hasher: &mut DefaultHasher) {
    let mut buf = [0u8; 8192];
    let mut off = start;
    while off < end {
        let want = ((end - off) as usize).min(buf.len());
        let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), want, off) };
        if n <= 0 {
            break;
        }
        hasher.write(&buf[..n as usize]);
        off += n as i64;
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RawFileHandle {
    handle_bytes: u32,
    handle_type: i32,
    f_handle: [u8; 128],
}

fn file_handle_bytes(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(target_os = "linux")]
    {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            format!(
                "name_to_handle_at refused non-c path {}; FileId NOT RUN",
                path.display()
            )
        })?;
        let mut raw = RawFileHandle {
            handle_bytes: 128,
            handle_type: 0,
            f_handle: [0; 128],
        };
        let mut mount_id: libc::c_int = 0;
        let rc = unsafe {
            libc::name_to_handle_at(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                (&mut raw as *mut RawFileHandle).cast(),
                &mut mount_id,
                0,
            )
        };
        if rc != 0 {
            return Err(format!(
                "name_to_handle_at failed at {}: {}; FileId NOT RUN",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let n = raw.handle_bytes as usize;
        if n == 0 {
            return Err(format!(
                "name_to_handle_at empty handle at {}; FileId NOT RUN",
                path.display()
            ));
        }
        if n > raw.f_handle.len() {
            return Err(format!(
                "name_to_handle_at handle too large at {}; FileId NOT RUN",
                path.display()
            ));
        }
        let mut out = Vec::with_capacity(8 + n);
        out.extend_from_slice(&mount_id.to_ne_bytes());
        out.extend_from_slice(&raw.handle_type.to_ne_bytes());
        out.extend_from_slice(&raw.f_handle[..n]);
        require_file_handle(out)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err("name_to_handle_at NOT RUN on this OS".into())
    }
}

/// Empty `name_to_handle_at` bytes are FileId NOT RUN, not identity.
pub fn require_file_handle(bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    if bytes.is_empty() {
        Err("name_to_handle_at empty handle; FileId NOT RUN".into())
    } else {
        Ok(bytes)
    }
}

fn file_id(path: &Path, meta: &fs::Metadata) -> Result<FileId, String> {
    let (dev, ino) = inode_of(meta);
    let size = file_len(meta);
    let handle = file_handle_bytes(path)?;
    Ok(FileId {
        dev,
        ino,
        ctime: inode_ctime(meta),
        size,
        content_hash: content_hash(path, meta),
        file_handle: handle,
    })
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

/// `$HOME/.cache` even when `XDG_CACHE_HOME` is set, plus `$TMPDIR`,
/// XDG cache/data/state/runtime, `/run/user/$UID`, and Mac Library dirs.
pub fn extra_watch_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    let home = std::env::var("HOME")
        .ok()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let uid = unsafe { libc::getuid() };
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
        ("XDG_RUNTIME_DIR", Some(run_user_uid_path(uid))),
    ] {
        if let Ok(value) = std::env::var(var) {
            if !value.is_empty() {
                roots.push(PathBuf::from(value));
            }
        }
        if let Some(path) = fallback {
            if !roots.iter().any(|root| root == &path) {
                roots.push(path);
            }
        }
    }
    if let Some(h) = home {
        roots.push(h.join("Library/Caches"));
        roots.push(h.join("Library/Application Support"));
    }
    roots
}

/// `/run/user/$UID`. Absent on this host; leftover proof is NOT RUN.
pub fn run_user_uid_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}"))
}

/// `$HOME` itself, inotify only. A rename dest at the home top is seen
/// without snapshot-walking the whole tree.
pub fn inotify_only_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            let path = PathBuf::from(home);
            if path.is_absolute() {
                roots.push(path);
            }
        }
    }
    roots
}

/// Writable temp roots a leftover census must snapshot: isolation extras
/// plus `/tmp`, `/var/tmp`, `/dev/shm`, and `$TMPDIR`.
pub fn writable_temp_roots() -> Vec<PathBuf> {
    let mut roots = extra_watch_roots();
    for extra in ["/tmp", "/var/tmp", "/dev/shm"] {
        let path = PathBuf::from(extra);
        if path.is_dir() && !roots.iter().any(|root| root == &path) {
            roots.push(path);
        }
    }
    if let Ok(tmpdir) = std::env::var("TMPDIR") {
        if !tmpdir.is_empty() {
            let path = PathBuf::from(tmpdir);
            if path.is_absolute() && !roots.iter().any(|root| root == &path) {
                roots.push(path);
            }
        }
    }
    roots
}

struct LiveWatch {
    fd: fs::File,
    wds: BTreeMap<i32, PathBuf>,
}

impl LiveWatch {
    fn open() -> Result<Self, String> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            return Err(format!(
                "inotify_init1 failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { fs::File::from_raw_fd(fd) };
        let mut watch = Self {
            fd,
            wds: BTreeMap::new(),
        };
        watch.add(&isolation_root())?;
        add_dir_watches_recursive(&mut watch, &isolation_root(), 0)?;
        for root in writable_temp_roots() {
            if root.exists() {
                watch.add(&root)?;
                add_dir_watches_recursive(&mut watch, &root, 0)?;
            }
        }
        for root in inotify_only_roots() {
            if root.exists() {
                watch.add(&root)?;
            }
        }
        Ok(watch)
    }

    fn add(&mut self, path: &Path) -> Result<i32, String> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| format!("inotify refused path {}", path.display()))?;
        let wd = unsafe {
            libc::inotify_add_watch(
                self.fd.as_raw_fd(),
                c_path.as_ptr(),
                libc::IN_CREATE
                    | libc::IN_DELETE
                    | libc::IN_MOVED_FROM
                    | libc::IN_MOVED_TO
                    | libc::IN_DELETE_SELF
                    | libc::IN_MOVE_SELF,
            )
        };
        if wd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                return Ok(-1);
            }
            return Err(format!(
                "inotify_add_watch {} failed: {err}",
                path.display()
            ));
        }
        self.wds.insert(wd, path.to_path_buf());
        Ok(wd)
    }

    fn drain(&mut self) -> Result<Vec<PathBuf>, String> {
        let mut seen = BTreeSet::new();
        let mut pending_dirs = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::WouldBlock {
                    break;
                }
                return Err(format!("inotify read failed: {err}"));
            }
            if n == 0 {
                break;
            }
            let n = n as usize;
            let mut offset = 0usize;
            let header = std::mem::size_of::<libc::inotify_event>();
            while offset + header <= n {
                let ev = unsafe { &*(buf.as_ptr().add(offset).cast::<libc::inotify_event>()) };
                if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                    return Err("inotify queue overflow; leftover watch fail closed".into());
                }
                let name = if ev.len > 0 {
                    let start = offset + header;
                    let end = start + ev.len as usize;
                    if end > n {
                        break;
                    }
                    let raw = &buf[start..end];
                    let nul = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                    Some(String::from_utf8_lossy(&raw[..nul]).into_owned())
                } else {
                    None
                };
                if let Some(dir) = self.wds.get(&ev.wd) {
                    let path = match &name {
                        Some(name) if !name.is_empty() => dir.join(name),
                        _ => dir.clone(),
                    };
                    if ev.mask & libc::IN_ISDIR != 0 && ev.mask & libc::IN_CREATE != 0 {
                        pending_dirs.push(path.clone());
                    }
                    seen.insert(path);
                }
                offset += header + ev.len as usize;
            }
        }
        for dir in pending_dirs {
            if self.add(&dir)? >= 0 {
                add_dir_watches_recursive(self, &dir, 0)?;
            }
        }
        Ok(seen.into_iter().collect())
    }
}

fn add_dir_watches_recursive(watch: &mut LiveWatch, root: &Path, depth: u32) -> Result<(), String> {
    if depth > 32 {
        return Ok(());
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(format!("inotify recurse refused {}: {err}", root.display()));
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && !path
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
        {
            if watch.add(&path)? >= 0 {
                add_dir_watches_recursive(watch, &path, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn start_live_watch() -> Result<(), String> {
    let watch = LiveWatch::open()?;
    *LIVE_WATCH.lock().expect("watch lock") = Some(watch);
    Ok(())
}

fn drain_live_watch() -> Result<Vec<PathBuf>, String> {
    let mut guard = LIVE_WATCH.lock().expect("watch lock");
    match guard.as_mut() {
        Some(watch) => watch.drain(),
        None => Err("run-window live watch was not started".into()),
    }
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
    for root in writable_temp_roots() {
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
    start_live_watch()?;
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
    snap.ids.insert(root.to_path_buf(), file_id(root, &meta)?);
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
/// Identity is (dev, inode, ctime, size+full-content hash, file handle).
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
        let id = file_id(path, &meta)?;
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
/// Includes files that existed only between the two snapshots (inotify).
/// Vanished inodes still reachable by handle or `(dev,ino)` are leftovers.
/// A short quiesce catches writers that land before return. A setsid write
/// after this function returns is HostPart::NotRun, never a closed PASS.
pub fn leftovers_in_run_window(before: &FsSnapshot) -> Result<Vec<PathBuf>, String> {
    let after = snapshot_run_window_unchecked()?;
    let mut found = collect_created(before, &after)?;
    for path in drain_live_watch()? {
        if !found.iter().any(|seen| seen == &path) {
            found.push(path);
        }
    }
    follow_vanished_handles(before, &after, &mut found)?;
    quiesce_run_window(before, &mut found)?;
    found.sort();
    Ok(found)
}

/// True when `open_by_handle_at` can still open the stored handle.
/// This host has no CAP_DAC_READ_SEARCH, so the call is usually EPERM;
/// the leftover dest is then found by `(dev,ino)` search.
pub fn handle_still_opens(handle: &[u8]) -> bool {
    match open_stored_handle(handle) {
        Ok(fd) => {
            unsafe { libc::close(fd) };
            true
        }
        Err(_) => false,
    }
}

fn open_stored_handle(handle: &[u8]) -> Result<i32, String> {
    if handle.len() < 8 {
        return Err("stored file handle too short; FileId NOT RUN".into());
    }
    let handle_type = i32::from_ne_bytes(handle[4..8].try_into().expect("handle type"));
    let body = &handle[8..];
    if body.is_empty() {
        return Err("stored file handle empty; FileId NOT RUN".into());
    }
    let mut raw = RawFileHandle {
        handle_bytes: body.len() as u32,
        handle_type,
        f_handle: [0; 128],
    };
    if body.len() > raw.f_handle.len() {
        return Err("stored file handle too large; FileId NOT RUN".into());
    }
    raw.f_handle[..body.len()].copy_from_slice(body);
    let mount = fs::File::open("/").map_err(|err| format!("open / for handle: {err}"))?;
    let fd = unsafe {
        libc::open_by_handle_at(
            mount.as_raw_fd(),
            (&mut raw as *mut RawFileHandle).cast(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open_by_handle_at: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

fn path_from_fd(fd: i32) -> Option<PathBuf> {
    let link = PathBuf::from(format!("/proc/self/fd/{fd}"));
    fs::read_link(link).ok().filter(|path| {
        let bytes = path.as_os_str().as_bytes();
        !bytes.ends_with(b" (deleted)")
    })
}

fn follow_vanished_handles(
    before: &FsSnapshot,
    after: &FsSnapshot,
    found: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let mut wanted = BTreeSet::new();
    for (path, old) in &before.ids {
        let vanished = !path.exists() || !after.paths.contains(path);
        if !vanished {
            continue;
        }
        wanted.insert((old.dev, old.ino));
        if handle_still_opens(&old.file_handle) {
            if let Ok(fd) = open_stored_handle(&old.file_handle) {
                if let Some(dest) = path_from_fd(fd) {
                    if !found.iter().any(|seen| seen == &dest) {
                        found.push(dest);
                    }
                } else if !found.iter().any(|seen| seen == path) {
                    found.push(path.clone());
                }
                unsafe { libc::close(fd) };
            } else if !found.iter().any(|seen| seen == path) {
                found.push(path.clone());
            }
        }
    }
    for dest in find_inode_paths(&wanted)? {
        if !found.iter().any(|seen| seen == &dest) {
            found.push(dest);
        }
    }
    Ok(())
}

fn find_inode_paths(wanted: &BTreeSet<(u64, u64)>) -> Result<Vec<PathBuf>, String> {
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut roots = vec![
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
        PathBuf::from("/dev/shm"),
    ];
    roots.extend(inotify_only_roots());
    roots.sort();
    roots.dedup();
    for root in roots {
        if root.exists() {
            search_inodes(&root, wanted, &mut found, 0)?;
        }
    }
    Ok(found)
}

fn search_inodes(
    root: &Path,
    wanted: &BTreeSet<(u64, u64)>,
    found: &mut Vec<PathBuf>,
    depth: u32,
) -> Result<(), String> {
    if depth > 8 || wanted.is_empty() {
        return Ok(());
    }
    let meta = match fs::symlink_metadata(root) {
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Ok(()),
        Ok(meta) => meta,
    };
    if wanted.contains(&inode_of(&meta)) && !found.iter().any(|seen| seen == root) {
        found.push(root.to_path_buf());
    }
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Ok(());
    }
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        search_inodes(&entry.path(), wanted, found, depth + 1)?;
    }
    Ok(())
}

fn quiesce_run_window(before: &FsSnapshot, found: &mut Vec<PathBuf>) -> Result<(), String> {
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(80));
        let after = snapshot_run_window_unchecked()?;
        let more = collect_created(before, &after)?;
        let mut grew = false;
        for path in more {
            if !found.iter().any(|seen| seen == &path) {
                found.push(path);
                grew = true;
            }
        }
        for path in drain_live_watch()? {
            if !found.iter().any(|seen| seen == &path) {
                found.push(path);
                grew = true;
            }
        }
        follow_vanished_handles(before, &after, found)?;
        if !grew {
            break;
        }
    }
    Ok(())
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

/// A setsid / double-fork write after `leftovers_in_run_window` returns
/// is outside the census. Name the limit. Never PASS as a closed window.
pub fn detached_child_after_return_host_part() -> HostPart {
    HostPart::NotRun(
        "leftovers_in_run_window returns before a setsid/double-fork child writes; detached write after return is NOT RUN, never a clean-window PASS"
            .into(),
    )
}

/// `mount --bind` / `unshare -m` leftover. This host refuses both.
pub fn bind_mount_host_part() -> HostPart {
    let mount = Command::new("mount")
        .args(["--bind", "/tmp", "/tmp"])
        .output();
    let unshare = Command::new("unshare").args(["-m", "--", "true"]).output();
    let mount_ok = mount
        .as_ref()
        .map(|out| out.status.success())
        .unwrap_or(false);
    let unshare_ok = unshare
        .as_ref()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if mount_ok || unshare_ok {
        HostPart::NotRun(
            "bind mount or unshare -m succeeded; bind leftover proof is NOT RUN, never PASS".into(),
        )
    } else {
        HostPart::NotRun(
            "mount --bind and unshare -m refused; bind leftover is NOT RUN, never PASS".into(),
        )
    }
}

/// Pid-namespace reuse. This host refuses `unshare -p`.
pub fn pid_namespace_host_part() -> HostPart {
    match Command::new("unshare")
        .args(["-p", "-f", "--mount-proc", "true"])
        .output()
    {
        Ok(out) if out.status.success() => HostPart::NotRun(
            "unshare -p succeeded; pid-namespace leftover proof is NOT RUN, never PASS".into(),
        ),
        Ok(out) => HostPart::NotRun(format!(
            "unshare -p refused ({}); pid-namespace leftover is NOT RUN, never PASS",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(err) => HostPart::NotRun(format!(
            "unshare missing ({err}); pid-namespace leftover is NOT RUN, never PASS"
        )),
    }
}

/// `/run/user/$UID` leftover. Absent here; never a clean-window PASS.
pub fn run_user_uid_host_part() -> HostPart {
    let uid = unsafe { libc::getuid() };
    let path = run_user_uid_path(uid);
    if path.is_dir() {
        HostPart::NotRun(format!(
            "{} exists but this lab has no planted leftover proof there; /run/user leftover is NOT RUN, never PASS",
            path.display()
        ))
    } else {
        HostPart::NotRun(format!(
            "{} is absent; /run/user leftover is NOT RUN, never PASS",
            path.display()
        ))
    }
}

/// Writing `max_user_watches`. This user cannot change the sysctl.
pub fn watch_sysctl_host_part() -> HostPart {
    let path = Path::new("/proc/sys/fs/inotify/max_user_watches");
    match fs::OpenOptions::new().write(true).open(path) {
        Ok(_file) => HostPart::NotRun(
            "max_user_watches is writable; watch-sysctl leftover proof is NOT RUN, never PASS"
                .into(),
        ),
        Err(err) => HostPart::NotRun(format!(
            "max_user_watches write refused ({err}); watch sysctl is NOT RUN, never PASS"
        )),
    }
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
        let existed_tmp = tmp.exists();
        let existed_storage = storage.exists();
        let path = write_isolated_leftover(&tmp, "storage", PLANTED_NAME, LEFTOVER_MARKER)?;
        let mut created = Vec::new();
        if !existed_storage {
            created.push(storage);
        }
        if !existed_tmp {
            created.push(tmp);
        }
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
    REAL_ROOT
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}
