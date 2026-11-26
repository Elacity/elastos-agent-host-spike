use std::fs::{self, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use serde::{Deserialize, Serialize};

/// An exclusive flock held for this guard's scope.
#[derive(Debug)]
pub struct FileLock(Option<fs::File>);

impl FileLock {
    /// Waits until this open file holds the exclusive lock.
    pub(crate) fn exclusive(file: fs::File) -> std::io::Result<Self> {
        file.lock()?;
        Ok(Self(Some(file)))
    }

    /// Takes the exclusive lock now or fails with `WouldBlock`.
    pub(crate) fn try_exclusive(file: fs::File) -> std::io::Result<Self> {
        Self::exclusive_within(file, Duration::ZERO)
    }

    /// Retries a busy lock until `wait` passes, then fails with `WouldBlock`.
    pub(crate) fn exclusive_within(file: fs::File, wait: Duration) -> std::io::Result<Self> {
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self(Some(file))),
                Err(fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Unlocks now and reports the result; dropping instead discards it.
    pub(crate) fn release(mut self) -> std::io::Result<()> {
        self.0.take().map_or(Ok(()), |file| file.unlock())
    }
}

impl std::ops::Deref for FileLock {
    type Target = fs::File;

    fn deref(&self) -> &fs::File {
        self.0.as_ref().expect("only release takes the file")
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // A command spawned meanwhile by another thread can retain this
        // description until its CLOEXEC fd closes at exec. The guard's scope
        // owns the lock, so release it before closing our fd.
        if let Some(file) = &self.0 {
            let _ = file.unlock();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProcessInfo {
    pub pid: u32,
    pub role: String,
    pub addr: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HostProcessMeta {
    pid: u32,
    role: String,
    addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    generation: String,
}

/// The managed runtime is a subordinate `elastos serve`. It does not heal
/// agent spend and it does not run agents.
pub(crate) fn is_subordinate_managed_runtime() -> bool {
    std::env::var_os("ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST").as_deref()
        == Some(std::ffi::OsStr::new("1"))
}

/// Take the host lock, then write every non-retired agent's stored total up
/// to its signed spend floor when that write can be done. The signed history
/// keeps its last 512 events. A floor is kept by the file once any heal or
/// charge has written it. If a write of the file was lost and no heal
/// succeeded and 512 other events came after, the floor is the file's.
///
/// `elastos gateway` and `elastos home --browser` (it starts this gateway)
/// pass `gateway`. The public gateway passes `gateway-public`. Standalone
/// `elastos serve` passes `serve`. The managed runtime does not call this.
/// The heal holds the agent file lock. The floor is already a signed spend
/// event, so the heal appends none. When the heal cannot be done, the cause is logged once and this still returns the host lock.
pub fn start_host_for_agents(data_dir: &Path, role: &str, addr: &str) -> anyhow::Result<FileLock> {
    let lock = acquire_host_process_lock(data_dir, role, addr)?;
    if let Err(reason) = crate::agents::raise_spend_file_to_signed_floor(data_dir) {
        tracing::warn!("agent spend heal did not run: {reason}");
    }
    Ok(lock)
}

pub fn acquire_host_process_lock(
    data_dir: &Path,
    role: &str,
    addr: &str,
) -> anyhow::Result<FileLock> {
    if !matches!(role, "update" | "update-recovery") {
        authorize_host_process_start(data_dir)?;
    }
    let lock = acquire_host_process_lock_inner(data_dir, role, addr)?;
    #[cfg(target_os = "macos")]
    if let Err(reason) = elastos_runtime::provider::recover_verified_copies(data_dir) {
        tracing::warn!("provider copy recovery skipped: {reason}");
    }
    Ok(lock)
}

pub(crate) fn acquire_principal_root_update_lock(
    data_dir: &Path,
    activation: &crate::install_transaction::SupportActivation<'_>,
) -> anyhow::Result<FileLock> {
    activation.authorize_principal_root_migration(data_dir)?;
    acquire_host_process_lock_inner(data_dir, "principal-root-upgrade", "offline")
}

fn acquire_host_process_lock_inner(
    data_dir: &Path,
    role: &str,
    addr: &str,
) -> anyhow::Result<FileLock> {
    fs::create_dir_all(data_dir)?;
    let lock_path = host_lock_path(data_dir);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open host lock {}", lock_path.display()))?;

    let lock = match FileLock::try_exclusive(file) {
        Ok(lock) => lock,
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            let holder = read_lock_metadata(&lock_path);
            let detail = holder
                .map(|meta| format!("pid {}, role '{}', addr {}", meta.pid, meta.role, meta.addr))
                .unwrap_or_else(|| "another ElastOS host process".to_string());
            return Err(anyhow!(
                "another ElastOS host already owns {} ({detail}). Stop it before starting a second live host with the same runtime identity. Use exactly one live host for this home, typically `elastos serve` or `elastos gateway`.",
                lock_path.display()
            ));
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("lock host process file {}", lock_path.display()));
        }
    };

    let meta = HostProcessMeta {
        pid: std::process::id(),
        role: role.to_string(),
        addr: addr.to_string(),
        generation: std::env::var("ELASTOS_UPDATE_GENERATION").unwrap_or_default(),
    };
    let mut file: &fs::File = &lock;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer_pretty(&mut file, &meta)?;
    writeln!(file)?;
    file.sync_data()?;

    Ok(lock)
}

pub fn authorize_host_process_start(data_dir: &Path) -> anyhow::Result<()> {
    crate::install_transaction::authorize_host_start(data_dir, &std::env::current_exe()?)
}

pub fn active_host_process(data_dir: &Path) -> anyhow::Result<Option<HostProcessInfo>> {
    let lock_path = host_lock_path(data_dir);
    if !lock_path.exists() {
        return Ok(None);
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open host lock {}", lock_path.display()))?;

    match FileLock::try_exclusive(file) {
        Ok(free) => {
            free.release()?;
            Ok(None)
        }
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(read_lock_metadata(&lock_path).map(Into::into))
        }
        Err(err) => Err(err).with_context(|| format!("inspect host lock {}", lock_path.display())),
    }
}

fn host_lock_path(data_dir: &Path) -> PathBuf {
    data_dir.join("host-process.lock")
}

fn read_lock_metadata(lock_path: &Path) -> Option<HostProcessMeta> {
    serde_json::from_slice(&fs::read(lock_path).ok()?).ok()
}

impl From<HostProcessMeta> for HostProcessInfo {
    fn from(value: HostProcessMeta) -> Self {
        Self {
            pid: value.pid,
            role: value.role,
            addr: value.addr,
        }
    }
}

#[derive(Debug, Clone)]
struct BinarySupersessionWatch {
    watch_path: PathBuf,
    watch_stamp: BinaryFileStamp,
    watch_sha256: String,
    /// The watched path is the canonical signed install, which is not the
    /// macOS private copy this process may have been exec'd from.
    follows_install: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BinaryFileStamp {
    len: u64,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    device_id: u64,
    #[cfg(unix)]
    inode: u64,
}

trait BinarySnapshotReader {
    fn current_exe_path_raw(&self) -> anyhow::Result<PathBuf>;
    fn metadata_stamp(&self, path: &Path) -> anyhow::Result<BinaryFileStamp>;
    fn digest_snapshot(&self, path: &Path) -> anyhow::Result<BinarySnapshot>;
}

#[derive(Debug, Clone, Copy)]
struct RealBinarySnapshotReader;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BinarySnapshot {
    stamp: BinaryFileStamp,
    sha256: String,
}

/// This process's private exec copy, when it was started from one.
#[cfg(target_os = "macos")]
pub type RunningExecCopy = Option<crate::setup::verified_executable::ExecCopyGuard>;
/// Other platforms do not exec from a private copy.
#[cfg(not(target_os = "macos"))]
pub type RunningExecCopy = Option<()>;

/// The running image keeps its private copy. On other platforms this is empty.
pub fn hold_running_exec_copy() -> anyhow::Result<RunningExecCopy> {
    #[cfg(target_os = "macos")]
    {
        crate::setup::verified_executable::adopt_running_exec_copy()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(None)
    }
}

pub fn spawn_installed_binary_supersession_watch(data_dir: &Path, role: &str) {
    let mut watch = match BinarySupersessionWatch::from_data_dir(data_dir) {
        Ok(watch) => watch,
        Err(err) => {
            // A private copy must not keep running when its install cannot be
            // watched. Every other process keeps the previous behaviour.
            #[cfg(target_os = "macos")]
            if std::env::current_exe().is_ok_and(|exe| {
                crate::setup::verified_executable::private_exec_dir(&exe).is_some()
            }) {
                eprintln!("[{role}] {err:#}. Exiting stale host.");
                std::process::exit(75);
            }
            let _ = err;
            return;
        }
    };
    let role = role.to_string();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if let Some(reason) = watch.superseded_reason() {
                eprintln!("[{}] {}", role, reason);
                #[cfg(target_os = "macos")]
                crate::setup::verified_executable::release_running_exec_copy();
                std::process::exit(75);
            }
        }
    });
}

impl BinarySupersessionWatch {
    fn from_data_dir(data_dir: &Path) -> anyhow::Result<Self> {
        Self::from_reader(data_dir, &RealBinarySnapshotReader)
    }

    fn from_reader(data_dir: &Path, reader: &impl BinarySnapshotReader) -> anyhow::Result<Self> {
        let _ = data_dir;
        let executing = normalize_deleted_exe_path(&reader.current_exe_path_raw()?);
        // Only macOS execs a private copy. Linux fexecve and Windows keep the
        // install path as current_exe, and that watch stays as it is.
        #[cfg(target_os = "macos")]
        if let Some((install, sha256)) = crate::binaries::signed_runtime_install(data_dir)? {
            let running = std::fs::canonicalize(&executing)
                .map_err(|error| anyhow!("running binary: {error}"))?;
            if running != install {
                let (actual, _) = crate::installed_release::file_digest(&running)?;
                anyhow::ensure!(
                    actual == sha256,
                    "running binary is not the installed release"
                );
            }
            let snapshot = reader.digest_snapshot(&install)?;
            anyhow::ensure!(
                snapshot.sha256 == sha256,
                "installed binary does not match its signed digest"
            );
            return Ok(Self {
                watch_path: install,
                watch_stamp: snapshot.stamp,
                watch_sha256: snapshot.sha256,
                follows_install: true,
            });
        }
        // A dev Home has no signed release. macOS execs that source path, so replacing it still exits 75.
        let snapshot = reader.digest_snapshot(&executing)?;
        Ok(Self {
            watch_path: executing,
            watch_stamp: snapshot.stamp,
            watch_sha256: snapshot.sha256,
            follows_install: false,
        })
    }

    fn superseded_reason(&mut self) -> Option<String> {
        self.superseded_reason_with(&RealBinarySnapshotReader)
    }

    fn superseded_reason_with(&mut self, reader: &impl BinarySnapshotReader) -> Option<String> {
        let current_exe_raw = match reader.current_exe_path_raw() {
            Ok(path) => path,
            Err(err) => {
                return Some(format!(
                    "host executable path could not be read for {}: {err:#}. Exiting stale host.",
                    self.watch_path.display()
                ));
            }
        };
        let raw_text = current_exe_raw.to_string_lossy();
        let current_exe = normalize_deleted_exe_path(&current_exe_raw);

        if raw_text.ends_with(" (deleted)") {
            return Some(format!(
                "host executable {} was replaced on disk. Exiting stale host.",
                self.watch_path.display()
            ));
        }

        // A private copy's path is not the install. It may differ, or disappear
        // after the parent returns, without the installed binary changing.
        if !self.follows_install && current_exe != self.watch_path {
            return Some(format!(
                "host executable moved from {} to {}. Exiting stale host.",
                self.watch_path.display(),
                current_exe.display()
            ));
        }

        let current_stamp = match reader.metadata_stamp(&self.watch_path) {
            Ok(stamp) => stamp,
            Err(err) => {
                return Some(format!(
                    "host executable {} could not be verified on disk: {err:#}. Exiting stale host.",
                    self.watch_path.display()
                ));
            }
        };

        if current_stamp == self.watch_stamp {
            return None;
        }

        let current_snapshot = match reader.digest_snapshot(&self.watch_path) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                return Some(format!(
                    "host executable {} changed on disk and could not be re-verified: {err:#}. Exiting stale host.",
                    self.watch_path.display()
                ));
            }
        };
        if current_snapshot.sha256 != self.watch_sha256 {
            return Some(format!(
                "host binary {} changed on disk. Exiting stale host so the newer binary can take over.",
                self.watch_path.display()
            ));
        }

        self.watch_stamp = current_snapshot.stamp;
        None
    }
}

fn current_exe_path_raw() -> anyhow::Result<PathBuf> {
    #[cfg(unix)]
    {
        fs::read_link("/proc/self/exe")
            .or_else(|_| std::env::current_exe())
            .map_err(Into::into)
    }

    #[cfg(not(unix))]
    {
        std::env::current_exe().map_err(Into::into)
    }
}

fn normalize_deleted_exe_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(stripped) = text.strip_suffix(" (deleted)") {
        return PathBuf::from(stripped);
    }
    path.to_path_buf()
}

fn metadata_stamp(path: &Path) -> anyhow::Result<BinaryFileStamp> {
    let metadata = fs::metadata(path)?;
    binary_file_stamp_from_metadata(&metadata)
}

fn sha256_file_streaming(path: &Path) -> anyhow::Result<BinarySnapshot> {
    use sha2::Digest as _;

    let mut file = fs::File::open(path)?;
    let stamp = metadata_stamp_from_file(&file)?;
    let mut sha = sha2::Sha256::new();
    let mut buf = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        sha.update(&buf[..read]);
    }
    Ok(BinarySnapshot {
        stamp,
        sha256: hex::encode(sha.finalize()),
    })
}

fn metadata_stamp_from_file(file: &fs::File) -> anyhow::Result<BinaryFileStamp> {
    let metadata = file.metadata()?;
    binary_file_stamp_from_metadata(&metadata)
}

fn binary_file_stamp_from_metadata(metadata: &fs::Metadata) -> anyhow::Result<BinaryFileStamp> {
    Ok(BinaryFileStamp {
        len: metadata.len(),
        modified: metadata.modified()?,
        #[cfg(unix)]
        device_id: {
            use std::os::unix::fs::MetadataExt as _;
            metadata.dev()
        },
        #[cfg(unix)]
        inode: {
            use std::os::unix::fs::MetadataExt as _;
            metadata.ino()
        },
    })
}

impl BinarySnapshotReader for RealBinarySnapshotReader {
    fn current_exe_path_raw(&self) -> anyhow::Result<PathBuf> {
        current_exe_path_raw()
    }

    fn metadata_stamp(&self, path: &Path) -> anyhow::Result<BinaryFileStamp> {
        metadata_stamp(path)
    }

    fn digest_snapshot(&self, path: &Path) -> anyhow::Result<BinarySnapshot> {
        sha256_file_streaming(path)
    }
}

#[cfg(unix)]
#[cfg(test)]
pub(crate) mod test_support {
    use std::os::fd::{FromRawFd as _, RawFd};
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};

    /// A command another thread spawns while this process has `path` open
    /// shares each open description of it until exec closes its CLOEXEC
    /// copies. This command keeps its copies across exec to hold that window
    /// open until the value drops.
    pub(crate) struct SpawnedWhileOpen(Child);

    impl SpawnedWhileOpen {
        pub(crate) fn new(path: &Path) -> Self {
            let target = std::fs::metadata(path).unwrap();
            let open: Vec<RawFd> = std::fs::read_dir("/dev/fd")
                .unwrap()
                .filter_map(|entry| {
                    let fd: RawFd = entry.ok()?.file_name().to_str()?.parse().ok()?;
                    // Inspect without owning: the descriptor is never closed here.
                    let open =
                        std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
                    let open = open.metadata().ok()?;
                    (open.dev() == target.dev() && open.ino() == target.ino()).then_some(fd)
                })
                .collect();
            assert!(!open.is_empty(), "{} is not open", path.display());
            let mut command = Command::new("/bin/sleep");
            command
                .arg("30")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    for &fd in &open {
                        if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            Self(command.spawn().unwrap())
        }
    }

    impl Drop for SpawnedWhileOpen {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// Whether another open description can take the exclusive lock on `path` now.
    pub(crate) fn lock_is_free(path: &Path) -> bool {
        super::FileLock::try_exclusive(std::fs::File::open(path).unwrap()).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    #[derive(Debug, Clone)]
    struct TestBinarySnapshotReader {
        state: Rc<TestBinarySnapshotReaderState>,
    }

    #[derive(Debug)]
    struct TestBinarySnapshotReaderState {
        current_exe_raw: RefCell<PathBuf>,
        digest_reads: Cell<usize>,
    }

    impl TestBinarySnapshotReader {
        fn new(path: PathBuf) -> Self {
            Self {
                state: Rc::new(TestBinarySnapshotReaderState {
                    current_exe_raw: RefCell::new(path),
                    digest_reads: Cell::new(0),
                }),
            }
        }

        fn set_current_exe_raw(&self, path: PathBuf) {
            *self.state.current_exe_raw.borrow_mut() = path;
        }

        fn digest_reads(&self) -> usize {
            self.state.digest_reads.get()
        }
    }

    impl BinarySnapshotReader for TestBinarySnapshotReader {
        fn current_exe_path_raw(&self) -> anyhow::Result<PathBuf> {
            Ok(self.state.current_exe_raw.borrow().clone())
        }

        fn metadata_stamp(&self, path: &Path) -> anyhow::Result<BinaryFileStamp> {
            metadata_stamp(path)
        }

        fn digest_snapshot(&self, path: &Path) -> anyhow::Result<BinarySnapshot> {
            self.state
                .digest_reads
                .set(self.state.digest_reads.get().saturating_add(1));
            sha256_file_streaming(path)
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write file");
    }

    fn test_watch(path: &Path) -> (BinarySupersessionWatch, TestBinarySnapshotReader) {
        let reader = TestBinarySnapshotReader::new(path.to_path_buf());
        let watch =
            BinarySupersessionWatch::from_reader(Path::new("/unused"), &reader).expect("watch");
        (watch, reader)
    }
    #[cfg(unix)]
    #[test]
    fn second_host_lock_for_same_data_dir_is_rejected() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _first = acquire_host_process_lock(temp.path(), "gateway", "127.0.0.1:8090")
            .expect("first lock");
        let err = acquire_host_process_lock(temp.path(), "serve", "0.0.0.0:3000")
            .expect_err("second lock should fail");
        assert!(
            err.to_string()
                .contains("another ElastOS host already owns"),
            "unexpected error: {err}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn live_provider_copy_survives_host_recovery_then_is_reaped() {
        use sha2::Digest as _;
        use std::io::Read as _;
        use std::os::unix::process::ExitStatusExt as _;

        const CHILD_HOME: &str = "ELASTOS_TEST_LIVE_COPY_HOME";
        if let Some(home) = std::env::var_os(CHILD_HOME) {
            let home = PathBuf::from(home);
            let binary = home.join("provider");
            let checksum = format!(
                "sha256:{:x}",
                sha2::Sha256::digest(fs::read(&binary).unwrap())
            );
            let _copy = elastos_runtime::provider::CheckedExecutable::pinned(&binary, &checksum)
                .unwrap()
                .with_home_data_dir(&home)
                .verify_at_spawn()
                .unwrap();
            let copy_dir = fs::read_dir(home.join("provider-copies"))
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            fs::write(home.join("copy-ready"), copy_dir.to_str().unwrap()).unwrap();
            std::io::stdin().read_exact(&mut [0u8]).unwrap();
            return;
        }

        let home = tempfile::tempdir().unwrap();
        fs::write(home.path().join("provider"), b"#!/bin/sh\nexit 0\n").unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_lock::tests::live_provider_copy_survives_host_recovery_then_is_reaped",
            ])
            .env(CHILD_HOME, home.path())
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let ready = home.path().join("copy-ready");
        for _ in 0..500 {
            if ready.exists() {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "copy owner exited early"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(ready.exists(), "copy owner did not become ready");
        let root = home.path().join("provider-copies");
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        let copy = PathBuf::from(fs::read_to_string(&ready).unwrap());
        let lock = acquire_host_process_lock(home.path(), "serve", "fixture").unwrap();
        assert!(copy.exists(), "the live provider owns this copy");
        drop(lock);
        child.kill().unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(copy.exists(), "SIGKILL leaves the copy for recovery");
        let _lock = acquire_host_process_lock(home.path(), "serve", "fixture").unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn provider_copy_recovery_problem_does_not_abort_host_start() {
        use std::os::unix::fs::PermissionsExt as _;

        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("provider-copies");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(elastos_runtime::provider::recover_verified_copies(home.path()).is_err());
        let lock = acquire_host_process_lock(home.path(), "serve", "fixture").unwrap();
        drop(lock);

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let stale = root.join("elastos-provider-ABC123");
        fs::create_dir(&stale).unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(stale.join(".copy-live.lock"), b"").unwrap();
        fs::set_permissions(
            stale.join(".copy-live.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let _lock = acquire_host_process_lock(home.path(), "serve", "fixture").unwrap();
        assert!(!stale.exists(), "host start also performs recovery");
    }

    #[cfg(unix)]
    #[test]
    fn model_host_lock_is_data_root_scoped() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first_root = temp.path().join("first-home");
        let second_root = temp.path().join("second-home");
        let first = acquire_host_process_lock(&first_root, "serve", "127.0.0.1:3100")
            .expect("first Home owns its data root");
        let second = acquire_host_process_lock(&second_root, "serve", "127.0.0.1:3101")
            .expect("a distinct Home in the same process owns a separate data root");
        for root in [&first_root, &second_root] {
            assert!(acquire_host_process_lock(root, "serve", "127.0.0.1:3102").is_err());
        }
        drop(first);
        let first = acquire_host_process_lock(&first_root, "serve", "127.0.0.1:3100")
            .expect("release affects only the first data root");
        assert!(acquire_host_process_lock(&second_root, "serve", "127.0.0.1:3102").is_err());
        drop(second);
        let _second = acquire_host_process_lock(&second_root, "serve", "127.0.0.1:3101")
            .expect("the second data root can take its own released lock");
        assert!(acquire_host_process_lock(&first_root, "serve", "127.0.0.1:3102").is_err());
        drop(first);
    }

    #[cfg(unix)]
    #[test]
    fn ended_host_lock_is_free_while_a_command_spawned_under_it_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let host = acquire_host_process_lock(temp.path(), "update-recovery", "offline")
            .expect("first lock");
        let _command = test_support::SpawnedWhileOpen::new(&host_lock_path(temp.path()));
        drop(host);
        acquire_host_process_lock(temp.path(), "update-recovery", "offline")
            .expect("the next host must not wait for a command spawned under the last");
    }

    #[cfg(unix)]
    #[test]
    fn released_lock_reports_ok_and_is_free_while_a_command_spawned_under_it_runs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("released.lock");
        let lock = FileLock::try_exclusive(fs::File::create(&path).expect("lock file"))
            .expect("first lock");
        let _command = test_support::SpawnedWhileOpen::new(&path);
        lock.release().expect("release reports its unlock");
        assert!(test_support::lock_is_free(&path));
    }
    #[cfg(unix)]
    #[test]
    fn active_host_process_reports_live_owner() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _first = acquire_host_process_lock(temp.path(), "gateway", "127.0.0.1:8090")
            .expect("first lock");
        let owner = active_host_process(temp.path())
            .expect("inspect owner")
            .expect("owner present");
        assert_eq!(owner.role, "gateway");
        assert_eq!(owner.addr, "127.0.0.1:8090");
    }

    #[test]
    fn normalize_deleted_exe_path_strips_linux_deleted_suffix() {
        let raw = PathBuf::from("/home/test/.local/bin/elastos (deleted)");
        assert_eq!(
            normalize_deleted_exe_path(&raw),
            PathBuf::from("/home/test/.local/bin/elastos")
        );
    }

    #[test]
    fn supersession_watch_startup_reads_one_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (_watch, reader) = test_watch(&exe);
        assert_eq!(reader.digest_reads(), 1);
    }

    #[test]
    fn supersession_watch_skips_digest_when_stamp_is_unchanged() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        for _ in 0..100 {
            assert_eq!(watch.superseded_reason_with(&reader), None);
        }
        assert_eq!(reader.digest_reads(), 1);
    }

    #[test]
    fn supersession_watch_updates_stamp_after_identical_bytes_rewrite() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"same bytes");

        let (mut watch, reader) = test_watch(&exe);
        let initial_reads = reader.digest_reads();

        let replacement = temp.path().join("replacement");
        write_file(&replacement, b"same bytes");
        // Two writes microseconds apart can share one file-clock tick (Windows ticks
        // are coarse), so give the replacement a clearly different mtime.
        // On Unix keep the original mtime so only the inode and device can reveal
        // the swap; Windows has no inode, so there the replacement is later.
        let original_mtime = fs::metadata(&exe)
            .expect("original metadata")
            .modified()
            .expect("mtime");
        #[cfg(not(unix))]
        let replacement_mtime = original_mtime + std::time::Duration::from_secs(2);
        #[cfg(unix)]
        let replacement_mtime = original_mtime;
        fs::File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_modified(replacement_mtime)
            .expect("set replacement mtime");
        fs::rename(&replacement, &exe).expect("replace file");

        assert_eq!(watch.superseded_reason_with(&reader), None);
        assert_eq!(reader.digest_reads(), initial_reads + 1);

        for _ in 0..100 {
            assert_eq!(watch.superseded_reason_with(&reader), None);
        }
        assert_eq!(reader.digest_reads(), initial_reads + 1);
    }

    #[test]
    fn supersession_watch_detects_same_path_content_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        let initial_reads = reader.digest_reads();
        write_file(&exe, b"changed content with a different length");

        let reason = watch.superseded_reason_with(&reader).expect("superseded");
        assert!(reason.contains("changed on disk"), "{reason}");
        assert_eq!(reader.digest_reads(), initial_reads + 1);
    }

    #[test]
    fn supersession_watch_detects_atomic_inode_replacement() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        let initial_reads = reader.digest_reads();
        let replacement = temp.path().join("replacement");
        write_file(&replacement, b"modified");
        // Same size as the original and written within one Windows file-clock
        // tick; Windows has no inode, so give the replacement a clearly later
        // mtime, as a real replacement has.
        // On Unix keep the original mtime so only the inode and device can reveal
        // the swap; Windows has no inode, so there the replacement is later.
        let original_mtime = fs::metadata(&exe)
            .expect("original metadata")
            .modified()
            .expect("mtime");
        #[cfg(not(unix))]
        let replacement_mtime = original_mtime + std::time::Duration::from_secs(2);
        #[cfg(unix)]
        let replacement_mtime = original_mtime;
        fs::File::options()
            .write(true)
            .open(&replacement)
            .expect("open replacement")
            .set_modified(replacement_mtime)
            .expect("set replacement mtime");
        fs::rename(&replacement, &exe).expect("replace file");

        let reason = watch.superseded_reason_with(&reader).expect("superseded");
        assert!(reason.contains("changed on disk"), "{reason}");
        assert_eq!(reader.digest_reads(), initial_reads + 1);
    }

    #[test]
    fn supersession_watch_detects_moved_executable_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        let moved = temp.path().join("elastos-new");
        reader.set_current_exe_raw(moved.clone());

        let reason = watch.superseded_reason_with(&reader).expect("superseded");
        assert!(reason.contains("moved"), "{reason}");
        assert!(reason.contains(&moved.display().to_string()), "{reason}");
    }

    #[test]
    fn supersession_watch_detects_deleted_executable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        fs::remove_file(&exe).expect("remove file");

        let reason = watch.superseded_reason_with(&reader).expect("superseded");
        assert!(reason.contains("could not be verified on disk"), "{reason}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn supersession_watch_follows_the_signed_install_not_the_private_copy() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = crate::installed_release::tests::Fixture::new();
        let install = fixture.data.join("runtime");
        let copy_dir = tempfile::tempdir().expect("copy dir");
        let copy = copy_dir.path().join("executable");
        fs::copy(&install, &copy).expect("copy install");
        fs::set_permissions(&copy, fs::Permissions::from_mode(0o500)).expect("copy mode");
        let reader = TestBinarySnapshotReader::new(copy.clone());
        let mut watch = BinarySupersessionWatch::from_reader(&fixture.data, &reader)
            .expect("watch the signed install");
        fs::remove_file(&copy).expect("delete private copy");
        assert!(
            watch.superseded_reason_with(&reader).is_none(),
            "a missing private copy is not a replaced install"
        );
        fs::write(&install, b"replaced signed runtime bytes").expect("replace install");
        let reason = watch
            .superseded_reason_with(&reader)
            .expect("replaced install");
        assert!(reason.contains("changed on disk"), "{reason}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn watch_setup_error_returns_when_this_process_is_not_a_private_copy() {
        let temp = tempfile::tempdir().expect("tempdir");
        fs::write(temp.path().join("sources.json"), b"{").expect("sources");
        let error = BinarySupersessionWatch::from_data_dir(temp.path())
            .expect_err("malformed sources must not arm the watch");
        assert!(
            crate::setup::verified_executable::private_exec_dir(&std::env::current_exe().unwrap())
                .is_none(),
            "the test process is not a private exec copy"
        );
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn supersession_watch_detects_linux_deleted_suffix() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exe = temp.path().join("elastos");
        write_file(&exe, b"original");

        let (mut watch, reader) = test_watch(&exe);
        reader.set_current_exe_raw(PathBuf::from(format!("{} (deleted)", exe.display())));

        let reason = watch.superseded_reason_with(&reader).expect("superseded");
        assert!(reason.contains("replaced on disk"), "{reason}");
    }
}
