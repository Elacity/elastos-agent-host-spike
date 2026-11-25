//! Keep the verified executable bytes selected until process creation.

use anyhow::{Context, Result};
use sha2::Digest;
#[cfg(target_os = "macos")]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct VerifiedExecutable {
    #[cfg(target_os = "linux")]
    file: File,
    /// Shared lock on the private copy. Drop releases it. None on a dev Home.
    #[cfg(target_os = "macos")]
    _copy_lock: Option<File>,
    #[cfg(target_os = "macos")]
    _private_dir: Option<tempfile::TempDir>,
    exec_path: PathBuf,
    content_sha256: String,
    /// The signed release digest these held bytes matched (none for a source
    /// Home's `dev_mode = true` start). A native provider start pins its
    /// spawn-time check to this same digest.
    checksum: Option<String>,
}

impl VerifiedExecutable {
    pub fn prepare(path: &Path, checksum: &str) -> Result<Self> {
        Self::hold(path, Some(checksum))
    }

    /// A source Home's `dev_mode = true` start: the same held bytes, no digest.
    pub(crate) fn unchecked(path: &Path) -> Result<Self> {
        Self::hold(path, None)
    }

    fn hold(path: &Path, checksum: Option<&str>) -> Result<Self> {
        #[cfg(target_os = "macos")]
        reap_dead_exec_copies();
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("cannot open installed executable {}", path.display()))?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "installed executable is not a regular file"
        );
        let content_sha256 = sha256_hex(&mut file)?;
        if let Some(checksum) = checksum {
            anyhow::ensure!(
                held_matches(checksum, &content_sha256, &mut file)?,
                "installed executable differs from signed release digest"
            );
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            // Standard I/O setup owns descriptors 0..2 in the child.
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error())
                    .context("cannot hold installed executable");
            }
            Ok(Self {
                file: unsafe { File::from_raw_fd(fd) },
                exec_path: format!("/proc/self/fd/{fd}").into(),
                content_sha256,
                checksum: checksum.map(str::to_owned),
            })
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt;
            // No signed digest: exec the source path so the watch follows that file.
            if checksum.is_none() {
                return Ok(Self {
                    _copy_lock: None,
                    _private_dir: None,
                    exec_path: path.to_path_buf(),
                    content_sha256,
                    checksum: None,
                });
            }
            let private_dir = tempfile::Builder::new()
                .prefix(EXEC_COPY_PREFIX)
                .tempdir()?;
            let mut directory_mode = fs::metadata(private_dir.path())?.permissions();
            directory_mode.set_mode(0o700);
            fs::set_permissions(private_dir.path(), directory_mode)?;
            // Lock before the byte copy so a crash mid-copy is reaped, and a
            // live copy cannot be reaped.
            let copy_lock = create_exec_copy_lock(private_dir.path())?;
            let exec_path = private_dir.path().join("executable");
            let mut copy = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&exec_path)?;
            file.seek(SeekFrom::Start(0))?;
            std::io::copy(&mut file, &mut copy)?;
            copy.sync_all()?;
            copy.set_permissions(fs::Permissions::from_mode(0o500))?;
            drop(copy);
            let mut copy = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&exec_path)?;
            anyhow::ensure!(
                sha256_hex(&mut copy)? == content_sha256,
                "private executable copy differs from the held executable"
            );
            // Age starts when the copy is ready, so a slow copy is not reaped.
            copy_lock.set_modified(std::time::SystemTime::now())?;
            Ok(Self {
                _copy_lock: Some(copy_lock),
                _private_dir: Some(private_dir),
                exec_path,
                content_sha256,
                checksum: checksum.map(str::to_owned),
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("installed executable launch is unsupported on this platform")
    }

    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    /// The detached child keeps this private directory after the parent returns.
    /// Short-lived commands leave cleanup on and delete the copy with this value.
    pub(crate) fn persist_private_copy(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(dir) = &mut self._private_dir {
            dir.disable_cleanup(true);
        }
    }

    /// Digest of the bytes read into this hold, not a later read of the caller path.
    pub(crate) fn held_content_sha256(&self) -> &str {
        &self.content_sha256
    }

    /// Native providers require a signed digest even in a source Home's
    /// `dev_mode`; refuse an unchecked executable before process creation.
    pub fn signed_checksum(&self) -> Result<&str> {
        self.checksum.as_deref().ok_or_else(|| {
            anyhow::anyhow!("no signed release digest (dev_mode start is unchecked)")
        })
    }

    /// Attach after the caller has set all arguments and environment changes.
    /// Linux executes the held descriptor; the visible command path is only a
    /// fallback for std's command construction and is never the exec target.
    pub fn attach_std(&self, command: &mut std::process::Command, clear_env: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::collections::BTreeMap;
            use std::ffi::{CString, OsString};
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::process::CommandExt;

            let mut argv = Vec::new();
            argv.push(CString::new(command.get_program().as_bytes())?);
            for arg in command.get_args() {
                argv.push(CString::new(arg.as_bytes())?);
            }
            let mut env: BTreeMap<OsString, OsString> = if clear_env {
                BTreeMap::new()
            } else {
                std::env::vars_os().collect()
            };
            for (key, value) in command.get_envs() {
                match value {
                    Some(value) => {
                        env.insert(key.to_os_string(), value.to_os_string());
                    }
                    None => {
                        env.remove(key);
                    }
                }
            }
            let env: Vec<CString> = env
                .into_iter()
                .map(|(key, value)| {
                    let mut bytes = key.as_bytes().to_vec();
                    bytes.push(b'=');
                    bytes.extend_from_slice(value.as_bytes());
                    CString::new(bytes)
                })
                .collect::<std::result::Result<_, _>>()?;
            let mut argv_ptrs: Vec<usize> =
                argv.iter().map(|value| value.as_ptr() as usize).collect();
            argv_ptrs.push(0);
            let mut env_ptrs: Vec<usize> =
                env.iter().map(|value| value.as_ptr() as usize).collect();
            env_ptrs.push(0);
            let fd = self.file.as_raw_fd();
            unsafe {
                command.pre_exec(move || {
                    // Script interpreters reopen the descriptor after exec.
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    libc::fexecve(fd, argv_ptrs.as_ptr().cast(), env_ptrs.as_ptr().cast());
                    let _keep_alive = (&argv, &env);
                    Err(std::io::Error::last_os_error())
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (command, clear_env);
        }
        Ok(())
    }

    pub fn attach_tokio(
        &self,
        command: &mut tokio::process::Command,
        clear_env: bool,
    ) -> Result<()> {
        self.attach_std(command.as_std_mut(), clear_env)
    }
}

fn held_matches(checksum: &str, held_sha256: &str, file: &mut File) -> Result<bool> {
    let (algorithm, expected) = checksum
        .split_once(':')
        .context("signed executable digest is malformed")?;
    match algorithm {
        "sha256" if expected.len() == 64 => Ok(held_sha256.eq_ignore_ascii_case(expected)),
        "sha512" if expected.len() == 128 => {
            file.seek(SeekFrom::Start(0))?;
            let mut buffer = [0u8; 8192];
            let mut digest = sha2::Sha512::new();
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                digest.update(&buffer[..n]);
            }
            Ok(hex::encode(digest.finalize()) == expected.to_ascii_lowercase())
        }
        _ => anyhow::bail!("signed executable digest is unsupported"),
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn age(path: &Path) {
        let file = File::open(path).unwrap();
        file.set_modified(
            std::time::SystemTime::now() - COPY_REAP_AFTER - std::time::Duration::from_secs(1),
        )
        .unwrap();
    }

    fn private_dir() -> PathBuf {
        let dir = tempfile::Builder::new()
            .prefix(EXEC_COPY_PREFIX)
            .tempdir()
            .unwrap();
        let mut mode = fs::metadata(dir.path()).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(dir.path(), mode).unwrap();
        dir.keep()
    }

    #[test]
    fn a_dropped_exec_copy_is_reaped_and_a_held_lock_is_kept() {
        let path = private_dir();
        let lock = create_exec_copy_lock(&path).unwrap();
        fs::write(path.join("executable"), b"copy").unwrap();
        let suffix = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix(EXEC_COPY_PREFIX))
            .unwrap();
        assert_eq!(suffix.len(), 6);
        age(&path);
        age(&path.join(EXEC_COPY_LOCK));
        reap_dead_exec_copies();
        assert!(path.exists(), "a held private copy was reaped");
        drop(lock);
        reap_dead_exec_copies();
        assert!(!path.exists(), "an old unlocked copy was left behind");
    }

    #[test]
    fn a_young_unlocked_copy_is_kept_and_an_old_one_is_reaped() {
        let path = private_dir();
        let lock = create_exec_copy_lock(&path).unwrap();
        drop(lock);
        reap_dead_exec_copies();
        assert!(
            path.exists(),
            "a copy whose lock just became free was reaped"
        );
        age(&path.join(EXEC_COPY_LOCK));
        reap_dead_exec_copies();
        assert!(!path.exists(), "an old unlocked copy was left behind");
    }

    #[test]
    fn a_lockless_copy_is_reaped_only_once_it_is_old() {
        let young = private_dir();
        reap_dead_exec_copies();
        assert!(young.exists(), "a new lockless copy was reaped");
        let old = private_dir();
        age(&old);
        let wrong_mode = private_dir();
        let mut mode = fs::metadata(&wrong_mode).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&wrong_mode, mode).unwrap();
        age(&wrong_mode);
        let wrong_name =
            std::env::temp_dir().join(format!("elastos-exec-not-{}", std::process::id()));
        fs::create_dir(&wrong_name).unwrap();
        let mut mode = fs::metadata(&wrong_name).unwrap().permissions();
        mode.set_mode(0o700);
        fs::set_permissions(&wrong_name, mode).unwrap();
        age(&wrong_name);
        reap_dead_exec_copies();
        assert!(!old.exists(), "an old lockless copy was left behind");
        assert!(young.exists(), "a new lockless copy was reaped");
        assert!(
            wrong_mode.exists(),
            "a directory with the wrong mode was reaped"
        );
        assert!(
            wrong_name.exists(),
            "a directory with the wrong name was reaped"
        );
        let _ = fs::remove_dir_all(&young);
        let _ = fs::remove_dir_all(&wrong_mode);
        let _ = fs::remove_dir_all(&wrong_name);
    }

    #[test]
    fn dev_unchecked_start_execs_the_source_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("elastos");
        fs::write(&path, b"dev-runtime").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        let held = VerifiedExecutable::unchecked(&path).unwrap();
        assert_eq!(held.exec_path(), path.as_path());
    }

    #[test]
    fn private_copy_recognition_is_name_and_owner_only() {
        let path = private_dir();
        let exe = path.join("executable");
        fs::write(&exe, b"x").unwrap();
        assert!(private_exec_dir(&exe).is_some());
        let mut mode = fs::metadata(&path).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&path, mode).unwrap();
        assert!(private_exec_dir(&exe).is_none());
        assert!(private_exec_dir(&std::env::current_exe().unwrap()).is_none());
        let _ = fs::remove_dir_all(&path);
    }

    /// Start from the private copy, age its lock past the reaper limit, and
    /// start another process from the same bytes. The hold is the one `main`
    /// takes for every host start.
    #[test]
    fn a_running_private_copy_is_held_through_the_reaper_and_starts_again() {
        const TEST: &str = "setup::verified_executable::tests::a_running_private_copy_is_held_through_the_reaper_and_starts_again";
        if std::env::var_os("ELASTOS_P28_REAP_GRAND").is_some() {
            fs::write(
                std::env::var("ELASTOS_P28_REAP_MARKER").unwrap(),
                b"started",
            )
            .unwrap();
            std::process::exit(0);
        }
        if std::env::var_os("ELASTOS_P28_REAP_CHILD").is_some() {
            let guard = crate::host_lock::hold_running_exec_copy().unwrap();
            if guard.is_none() {
                eprintln!("child did not hold its private copy");
                std::process::exit(3);
            }
            let exe = std::env::current_exe().unwrap();
            fs::write(std::env::var("ELASTOS_P28_REAP_HELD").unwrap(), b"held").unwrap();
            let go = std::env::var("ELASTOS_P28_REAP_GO").unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
            while !Path::new(&go).exists() {
                if std::time::Instant::now() > deadline {
                    eprintln!("parent did not drop the copy");
                    std::process::exit(4);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            age(&exe.parent().unwrap().join(EXEC_COPY_LOCK));
            reap_dead_exec_copies();
            if !exe.exists() {
                eprintln!("reaper deleted the running copy");
                std::process::exit(5);
            }
            let output = std::process::Command::new(&exe)
                .arg("--exact")
                .arg(TEST)
                .env("ELASTOS_P28_REAP_GRAND", "1")
                .env(
                    "ELASTOS_P28_REAP_MARKER",
                    std::env::var("ELASTOS_P28_REAP_MARKER").unwrap(),
                )
                .output()
                .unwrap();
            if !output.status.success() {
                eprintln!("{}", String::from_utf8_lossy(&output.stderr));
                std::process::exit(6);
            }
            drop(guard);
            std::process::exit(0);
        }

        let root = tempfile::tempdir().unwrap();
        let held_flag = root.path().join("held");
        let go = root.path().join("go");
        let marker = root.path().join("started");
        let exe = std::env::current_exe().unwrap();
        let mut file = File::open(&exe).unwrap();
        let digest = super::sha256_hex(&mut file).unwrap();
        let mut prepared = VerifiedExecutable::prepare(&exe, &format!("sha256:{digest}")).unwrap();
        let child = std::process::Command::new(prepared.exec_path())
            .arg("--exact")
            .arg(TEST)
            .env("ELASTOS_P28_REAP_CHILD", "1")
            .env("ELASTOS_P28_REAP_HELD", &held_flag)
            .env("ELASTOS_P28_REAP_GO", &go)
            .env("ELASTOS_P28_REAP_MARKER", &marker)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while !held_flag.exists() {
            if std::time::Instant::now() > deadline {
                panic!("child did not take the private-copy lock");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        prepared.persist_private_copy();
        drop(prepared);
        fs::write(&go, b"go").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "stdout {} stderr {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(&marker).unwrap(), b"started");
    }
}

#[cfg(target_os = "macos")]
const EXEC_COPY_PREFIX: &str = "elastos-exec-";
#[cfg(target_os = "macos")]
const EXEC_COPY_LOCK: &str = ".exec-copy.lock";
#[cfg(target_os = "macos")]
const COPY_REAP_AFTER: std::time::Duration = std::time::Duration::from_secs(60);

/// The private directory of the running image, when this process was exec'd
/// from one. The path is the kernel's executable path, not an environment value.
#[cfg(target_os = "macos")]
pub(crate) fn private_exec_dir(exe: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    if exe.file_name().and_then(|name| name.to_str()) != Some("executable") {
        return None;
    }
    let dir = exe.parent()?;
    let suffix = dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix(EXEC_COPY_PREFIX))?;
    if suffix.len() != 6 || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let meta = fs::symlink_metadata(dir).ok()?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o777 != 0o700 {
        return None;
    }
    Some(dir.to_path_buf())
}

#[cfg(target_os = "macos")]
fn create_exec_copy_lock(dir: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(EXEC_COPY_LOCK))
        .with_context(|| format!("cannot create private exec copy lock in {}", dir.display()))?;
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .context("cannot set private exec copy lock permissions")?;
    file.lock_shared()
        .context("cannot hold private exec copy lock")?;
    Ok(file)
}

#[cfg(target_os = "macos")]
fn open_exec_copy_lock(dir: &Path) -> Result<File> {
    use std::os::unix::fs::MetadataExt;
    let path = dir.join(EXEC_COPY_LOCK);
    let listed = fs::symlink_metadata(&path)
        .with_context(|| format!("private exec copy lock {}", path.display()))?;
    anyhow::ensure!(
        listed.is_file()
            && listed.nlink() == 1
            && listed.uid() == unsafe { libc::geteuid() }
            && listed.mode() & 0o777 == 0o600,
        "private exec copy lock has unsafe ownership or permissions"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let opened = file.metadata()?;
    anyhow::ensure!(
        (opened.dev(), opened.ino()) == (listed.dev(), listed.ino()),
        "private exec copy lock changed"
    );
    file.lock_shared()
        .context("cannot hold private exec copy lock")?;
    Ok(file)
}

/// Holds the caller's private exec copy until drop, then removes it.
#[cfg(target_os = "macos")]
pub struct ExecCopyGuard {
    dir: PathBuf,
    _lock: File,
}

#[cfg(target_os = "macos")]
impl Drop for ExecCopyGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// `Ok(None)` when this process was not started from a private exec copy.
#[cfg(target_os = "macos")]
pub(crate) fn adopt_running_exec_copy() -> Result<Option<ExecCopyGuard>> {
    let Ok(exe) = std::env::current_exe() else {
        return Ok(None);
    };
    let Some(dir) = private_exec_dir(&exe) else {
        return Ok(None);
    };
    let lock = open_exec_copy_lock(&dir)?;
    Ok(Some(ExecCopyGuard { dir, _lock: lock }))
}

/// Removes this process's private exec copy. `process::exit` skips destructors,
/// so the supersession watch calls this before it exits.
#[cfg(target_os = "macos")]
pub(crate) fn release_running_exec_copy() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let Some(dir) = private_exec_dir(&exe) else {
        return;
    };
    let _ = fs::remove_dir_all(dir);
}

#[cfg(target_os = "macos")]
fn copy_is_old(meta: &fs::Metadata) -> bool {
    matches!(meta.modified().ok().and_then(|m| m.elapsed().ok()), Some(age) if age >= COPY_REAP_AFTER)
}

/// Deletes old unused copies. No lock: name and owner only. A young or held lock stays.
#[cfg(target_os = "macos")]
pub(crate) fn reap_dead_exec_copies() {
    use std::os::unix::fs::MetadataExt;
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            continue;
        };
        let Some(suffix) = text.strip_prefix(EXEC_COPY_PREFIX) else {
            continue;
        };
        if suffix.len() != 6 || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            continue;
        }
        let dir = entry.path();
        let Ok(dir_meta) = fs::symlink_metadata(&dir) else {
            continue;
        };
        if !dir_meta.is_dir()
            || dir_meta.uid() != unsafe { libc::geteuid() }
            || dir_meta.mode() & 0o777 != 0o700
        {
            continue;
        }
        let lock_path = dir.join(EXEC_COPY_LOCK);
        let lock_meta = match fs::symlink_metadata(&lock_path) {
            Ok(meta) => meta,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && copy_is_old(&dir_meta) =>
            {
                if fs::symlink_metadata(&dir).is_ok_and(|again| {
                    (again.dev(), again.ino(), again.uid(), again.mode() & 0o777)
                        == (dir_meta.dev(), dir_meta.ino(), dir_meta.uid(), 0o700)
                }) && fs::symlink_metadata(&lock_path)
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound)
                {
                    let _ = fs::remove_dir_all(&dir);
                }
                continue;
            }
            Err(_) => continue,
        };
        if !copy_is_old(&lock_meta)
            || !lock_meta.is_file()
            || lock_meta.nlink() != 1
            || lock_meta.uid() != unsafe { libc::geteuid() }
            || lock_meta.mode() & 0o777 != 0o600
        {
            continue;
        }
        let Ok(lock) = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
        else {
            continue;
        };
        let Ok(opened) = lock.metadata() else {
            continue;
        };
        if (opened.dev(), opened.ino()) != (lock_meta.dev(), lock_meta.ino()) {
            continue;
        }
        if lock.try_lock().is_err() {
            continue;
        }
        let Ok(current_dir) = fs::symlink_metadata(&dir) else {
            continue;
        };
        let Ok(current_lock) = fs::symlink_metadata(&lock_path) else {
            continue;
        };
        if (current_dir.dev(), current_dir.ino()) != (dir_meta.dev(), dir_meta.ino())
            || (current_lock.dev(), current_lock.ino()) != (lock_meta.dev(), lock_meta.ino())
        {
            continue;
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

fn sha256_hex(file: &mut File) -> Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut digest = sha2::Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    Ok(hex::encode(digest.finalize()))
}
