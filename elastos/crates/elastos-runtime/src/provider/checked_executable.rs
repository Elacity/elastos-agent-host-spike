//! An executable pinned by the caller's verified release metadata.
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::io::{Seek, SeekFrom};
#[cfg(target_os = "macos")]
use std::os::fd::{AsRawFd as _, FromRawFd as _};
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt as _;
#[cfg(target_os = "linux")]
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::fs::FileExt as _,
};
use std::{
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct PreparedExecutable {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    /// The verified bytes start with `#!`. Only a script needs its descriptor
    /// after exec, because its interpreter reopens `/proc/self/fd/N`.
    #[cfg(target_os = "linux")]
    script: bool,
    /// Removing this directory removes the only path to the verified copy.
    /// The provider bridge owns it until the provider process is reaped, so a
    /// provider that resolves `current_exe()` after Init still finds itself.
    /// The lock survives exec in the provider, so recovery leaves a live copy
    /// alone even if its parent Runtime exits first.
    #[cfg(target_os = "macos")]
    _private_dir: tempfile::TempDir,
    #[cfg(target_os = "macos")]
    _liveness_lock: std::fs::File,
    exec_path: PathBuf,
}

#[cfg(target_os = "macos")]
const COPY_PREFIX: &str = "elastos-provider-";
#[cfg(target_os = "macos")]
const COPY_LOCK: &str = ".copy-live.lock";
#[cfg(target_os = "macos")]
fn copy_root(data_dir: &Path) -> PathBuf {
    data_dir.join("provider-copies")
}

#[cfg(target_os = "macos")]
fn private_copy_root(data_dir: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    if create {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| format!("provider copy Home cannot be created: {e}"))?;
    }
    let home = std::fs::symlink_metadata(data_dir)
        .map_err(|e| format!("provider copy Home cannot be inspected: {e}"))?;
    if !home.is_dir()
        || home.uid() != unsafe { libc::geteuid() }
        || home.permissions().mode() & 0o022 != 0
    {
        return Err("provider copy Home has unsafe ownership or permissions".into());
    }
    let root = copy_root(data_dir);
    if create {
        use std::os::unix::fs::DirBuilderExt as _;
        match std::fs::DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "provider copy directory cannot be created: {error}"
                ))
            }
        }
    }
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "provider copy directory cannot be inspected: {error}"
            ))
        }
    };
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err("provider copy directory has unsafe ownership or permissions".into());
    }
    Ok(Some(root))
}

#[cfg(target_os = "macos")]
fn create_copy_lock(directory: &Path) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(COPY_LOCK))
        .map_err(|e| format!("provider copy lock cannot be created: {e}"))?;
    // A provider's standard streams can replace descriptors below three.
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(format!(
            "provider copy lock descriptor cannot be held: {}",
            std::io::Error::last_os_error()
        ));
    }
    let held = unsafe { std::fs::File::from_raw_fd(fd) };
    if unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
        return Err(format!(
            "provider copy lock cannot be held: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(held)
}

/// Recover only copies whose own lock is free. Commands that start providers
/// without the Home host lock can still own copies in this directory.
#[cfg(target_os = "macos")]
pub fn recover_verified_copies(data_dir: &Path) -> Result<(), String> {
    let Some(root) = private_copy_root(data_dir, false)? else {
        return Ok(());
    };
    let entries = std::fs::read_dir(&root)
        .map_err(|e| format!("provider copy directory cannot be listed: {e}"))?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                tracing::warn!("provider copy entry cannot be read: {error}");
                continue;
            }
        };
        let name = entry.file_name();
        let Some(suffix) = name
            .to_str()
            .and_then(|name| name.strip_prefix(COPY_PREFIX))
        else {
            continue;
        };
        if suffix.len() != 6 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
            continue;
        }
        let path = entry.path();
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(path = %path.display(), "provider copy cannot be inspected: {error}");
                continue;
            }
        };
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            continue;
        }
        let lock_path = path.join(COPY_LOCK);
        let lock_meta = match std::fs::symlink_metadata(&lock_path) {
            Ok(meta)
                if meta.is_file()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.permissions().mode() & 0o777 == 0o600 =>
            {
                meta
            }
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::warn!(path = %lock_path.display(), "provider copy lock cannot be inspected: {error}");
                continue;
            }
        };
        let lock = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(path = %lock_path.display(), "provider copy lock cannot be opened: {error}");
                continue;
            }
        };
        let opened = match lock.metadata() {
            Ok(meta) if (meta.dev(), meta.ino()) == (lock_meta.dev(), lock_meta.ino()) => meta,
            Ok(_) => continue,
            Err(error) => {
                tracing::warn!(path = %lock_path.display(), "provider copy lock changed: {error}");
                continue;
            }
        };
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock {
                tracing::warn!(path = %lock_path.display(), "provider copy lock cannot be taken: {error}");
            }
            continue;
        }
        if !matches!(std::fs::symlink_metadata(&lock_path), Ok(current)
            if (current.dev(), current.ino()) == (opened.dev(), opened.ino()))
        {
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(current) if (metadata.dev(), metadata.ino()) == (current.dev(), current.ino()) => {}
            Ok(_) => continue,
            Err(error) => {
                tracing::warn!(path = %path.display(), "provider copy changed during recovery: {error}");
                continue;
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&path) {
            tracing::warn!(path = %path.display(), "provider copy cannot be removed: {error}");
        }
    }
    Ok(())
}

impl PreparedExecutable {
    pub(super) fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    #[cfg(target_os = "linux")]
    pub(super) fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn configure_command(&self, command: &mut tokio::process::Command) {
        use std::os::unix::process::CommandExt as _;
        // The kernel loads a native executable from /proc/self/fd/N before
        // close-on-exec runs, so an ELF provider inherits no extra descriptor.
        if !self.script {
            return;
        }
        let fd = self.fd();
        // A script interpreter reopens /proc/self/fd/N after exec, so the
        // child's descriptor must survive exec. The parent retains CLOEXEC.
        unsafe {
            command.as_std_mut().pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn configure_command(&self, command: &mut tokio::process::Command) {
        use std::os::unix::process::CommandExt as _;
        let fd = self._liveness_lock.as_raw_fd();
        unsafe {
            command.as_std_mut().pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// The release owner supplies the signed component checksum. Runtime checks it
/// again immediately before each provider process starts.
pub struct CheckedExecutable {
    path: PathBuf,
    digest: [u8; 32],
    refusal: Option<String>,
    siblings: Vec<&'static str>,
    home_data_dir: Option<PathBuf>,
}

impl CheckedExecutable {
    pub fn pinned(path: &Path, checksum: &str) -> Result<Self, String> {
        let hex = checksum.strip_prefix("sha256:").unwrap_or("");
        let bytes = hex::decode(hex)
            .map_err(|_| "provider executable has an invalid SHA-256 release pin")?;
        let digest: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "provider executable has an invalid SHA-256 release pin")?;
        Ok(Self {
            path: path.to_path_buf(),
            digest,
            refusal: None,
            siblings: Vec::new(),
            home_data_dir: None,
        })
    }

    pub fn refused(path: &Path, reason: String) -> Self {
        Self {
            path: path.to_path_buf(),
            digest: [0; 32],
            refusal: Some(reason),
            siblings: Vec::new(),
            home_data_dir: None,
        }
    }

    /// Bind the verified provider's private copy to the Home it serves.
    pub fn with_home_data_dir(mut self, data_dir: &Path) -> Self {
        self.home_data_dir = Some(data_dir.to_path_buf());
        self
    }

    /// Names a companion file the provider finds beside its own executable.
    /// On macOS the provider runs from a private copy, so the copy's directory
    /// links each named companion back to the installed one. Runtime does not
    /// execute or vouch for the companion; the provider resolves the same
    /// installed file it would resolve without the copy.
    pub fn with_sibling(mut self, name: &'static str) -> Self {
        self.siblings.push(name);
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify_at_spawn(&self) -> Result<PreparedExecutable, String> {
        if let Some(reason) = &self.refusal {
            return Err(reason.clone());
        }
        let before = std::fs::symlink_metadata(&self.path)
            .map_err(|e| format!("provider executable cannot be inspected: {e}"))?;
        if before.file_type().is_symlink() {
            return Err("provider executable symlink is refused".into());
        }
        if !before.is_file() {
            return Err("provider executable is not a regular file".into());
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .map_err(|e| format!("provider executable cannot be opened: {e}"))?;
        let opened = file
            .metadata()
            .map_err(|e| format!("provider executable cannot be inspected: {e}"))?;
        let mut hash = Sha256::new();
        std::io::copy(&mut file, &mut hash)
            .map_err(|e| format!("provider executable cannot be read: {e}"))?;
        let after = std::fs::symlink_metadata(&self.path)
            .map_err(|e| format!("provider executable changed during verification: {e}"))?;
        if (after.dev(), after.ino(), after.len()) != (opened.dev(), opened.ino(), opened.len()) {
            return Err("provider executable changed during verification".into());
        }
        if hash.finalize().as_slice() != self.digest {
            return Err("provider executable differs from verified release checksum".into());
        }
        #[cfg(target_os = "linux")]
        {
            // An fd below 3 could be replaced by the child's standard I/O.
            let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(format!(
                    "provider executable descriptor cannot be held: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut magic = [0u8; 2];
            let read = file
                .read_at(&mut magic, 0)
                .map_err(|e| format!("provider executable cannot be read: {e}"))?;
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            Ok(PreparedExecutable {
                file,
                script: read == 2 && magic == *b"#!",
                exec_path: format!("/proc/self/fd/{fd}").into(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            let data_dir = self
                .home_data_dir
                .as_ref()
                .ok_or("provider executable copy requires a Home data directory")?;
            let root = private_copy_root(data_dir, true)?.unwrap();
            let private_dir = tempfile::Builder::new()
                .prefix(COPY_PREFIX)
                .tempdir_in(&root)
                .map_err(|e| format!("provider executable copy cannot be created: {e}"))?;
            std::fs::set_permissions(private_dir.path(), std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("provider executable copy cannot be made private: {e}"))?;
            let liveness_lock = create_copy_lock(private_dir.path())?;
            let exec_path = private_dir.path().join("provider");
            let mut copy = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&exec_path)
                .map_err(|e| format!("provider executable copy cannot be created: {e}"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|e| format!("provider executable cannot be reread: {e}"))?;
            std::io::copy(&mut file, &mut copy)
                .map_err(|e| format!("provider executable cannot be copied: {e}"))?;
            copy.sync_all()
                .map_err(|e| format!("provider executable copy cannot be synced: {e}"))?;
            copy.set_permissions(std::fs::Permissions::from_mode(0o500))
                .map_err(|e| format!("provider executable copy cannot be sealed: {e}"))?;
            drop(copy);
            let mut copy = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&exec_path)
                .map_err(|e| format!("provider executable copy cannot be reopened: {e}"))?;
            let mut copied_hash = Sha256::new();
            std::io::copy(&mut copy, &mut copied_hash)
                .map_err(|e| format!("provider executable copy cannot be read: {e}"))?;
            if copied_hash.finalize().as_slice() != self.digest {
                return Err(
                    "provider executable copy differs from verified release checksum".into(),
                );
            }
            if !self.siblings.is_empty() {
                let installed_dir = self
                    .path
                    .parent()
                    .and_then(|parent| std::fs::canonicalize(parent).ok())
                    .ok_or("provider executable directory cannot be resolved")?;
                for name in &self.siblings {
                    let mut parts = Path::new(name).components();
                    if !matches!(
                        (parts.next(), parts.next()),
                        (Some(std::path::Component::Normal(_)), None)
                    ) {
                        return Err("provider sibling name is invalid".into());
                    }
                    let installed = installed_dir.join(name);
                    if installed.is_file() {
                        std::os::unix::fs::symlink(&installed, private_dir.path().join(name))
                            .map_err(|e| format!("provider sibling cannot be linked: {e}"))?;
                    }
                }
            }
            Ok(PreparedExecutable {
                _private_dir: private_dir,
                _liveness_lock: liveness_lock,
                exec_path,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err("provider executable execution is unsupported on this OS".into())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_recovery_tests {
    use super::*;

    #[tokio::test]
    async fn provider_keeps_copy_lock_after_parent_releases_it() {
        let home = tempfile::tempdir().unwrap();
        let binary = home.path().join("provider");
        std::fs::write(&binary, b"#!/bin/sh\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let checksum = format!(
            "sha256:{:x}",
            Sha256::digest(std::fs::read(&binary).unwrap())
        );
        let prepared = CheckedExecutable::pinned(&binary, &checksum)
            .unwrap()
            .with_home_data_dir(home.path())
            .verify_at_spawn()
            .unwrap();
        let mut command = tokio::process::Command::new(prepared.exec_path());
        prepared.configure_command(&mut command);
        let mut child = command.kill_on_drop(true).spawn().unwrap();
        let PreparedExecutable {
            _private_dir,
            _liveness_lock,
            exec_path,
        } = prepared;
        // Simulate parent death: the directory remains, but its descriptor closes.
        std::mem::forget(_private_dir);
        drop(_liveness_lock);
        assert!(
            child.try_wait().unwrap().is_none(),
            "provider exited before recovery"
        );
        recover_verified_copies(home.path()).unwrap();
        assert!(exec_path.exists(), "the provider inherited the lock");
        child.kill().await.unwrap();
        recover_verified_copies(home.path()).unwrap();
        assert!(!exec_path.exists(), "the reaped provider released its lock");
    }

    #[test]
    fn checked_executable_recovery_removes_only_owned_copies() {
        let home = tempfile::tempdir().unwrap();
        let root = private_copy_root(home.path(), true).unwrap().unwrap();
        let stale = tempfile::Builder::new()
            .prefix(COPY_PREFIX)
            .tempdir_in(&root)
            .unwrap();
        let stale_path = stale.path().to_path_buf();
        std::fs::set_permissions(&stale_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(create_copy_lock(&stale_path).unwrap());
        let target = home.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, stale_path.join("external")).unwrap();
        std::mem::forget(stale);
        let foreign = root.join("other-provider-ABCDEF");
        std::fs::create_dir(&foreign).unwrap();
        let link = root.join("elastos-provider-ABCDEF");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let linked_lock = root.join("elastos-provider-LOCK12");
        std::fs::create_dir(&linked_lock).unwrap();
        std::fs::set_permissions(&linked_lock, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&target, linked_lock.join(COPY_LOCK)).unwrap();

        recover_verified_copies(home.path()).unwrap();
        assert!(!stale_path.exists(), "{}", stale_path.display());
        assert!(foreign.exists());
        assert!(link.exists());
        assert!(linked_lock.exists());
        assert!(target.exists());
    }

    #[test]
    fn checked_executable_recovery_refuses_unsafe_root() {
        let home = tempfile::tempdir().unwrap();
        let root = private_copy_root(home.path(), true).unwrap().unwrap();
        let copy = tempfile::Builder::new()
            .prefix(COPY_PREFIX)
            .tempdir_in(&root)
            .unwrap();
        let copy_path = copy.path().to_path_buf();
        std::fs::set_permissions(&copy_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(create_copy_lock(&copy_path).unwrap());
        std::mem::forget(copy);
        // The caller warns and continues when this root is unsafe.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        assert!(recover_verified_copies(home.path()).is_err());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        recover_verified_copies(home.path()).unwrap();
        assert!(!copy_path.exists(), "{}", copy_path.display());
    }

    #[test]
    fn checked_executable_recovery_continues_after_undeletable_copy() {
        let home = tempfile::tempdir().unwrap();
        let root = private_copy_root(home.path(), true).unwrap().unwrap();
        let blocked = tempfile::Builder::new()
            .prefix(COPY_PREFIX)
            .tempdir_in(&root)
            .unwrap();
        let blocked_path = blocked.path().to_path_buf();
        std::fs::set_permissions(&blocked_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(create_copy_lock(&blocked_path).unwrap());
        let inner = blocked_path.join("inner");
        std::fs::create_dir(&inner).unwrap();
        std::fs::write(inner.join("file"), b"held").unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o500)).unwrap();
        std::mem::forget(blocked);
        let removable = tempfile::Builder::new()
            .prefix(COPY_PREFIX)
            .tempdir_in(&root)
            .unwrap();
        let removable_path = removable.path().to_path_buf();
        std::fs::set_permissions(&removable_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(create_copy_lock(&removable_path).unwrap());
        std::mem::forget(removable);

        recover_verified_copies(home.path()).unwrap();
        assert!(blocked_path.exists());
        assert!(!removable_path.exists());
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        recover_verified_copies(home.path()).unwrap();
        assert!(!blocked_path.exists());
    }
}

impl std::ops::Deref for CheckedExecutable {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.path()
    }
}

#[cfg(test)]
impl CheckedExecutable {
    pub(super) fn for_test(path: &Path) -> Self {
        let bytes = std::fs::read(path).unwrap_or_default();
        Self {
            path: path.to_path_buf(),
            digest: Sha256::digest(bytes).into(),
            refusal: None,
            siblings: Vec::new(),
            home_data_dir: path.parent().map(Path::to_path_buf),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn only_a_script_keeps_its_descriptor_across_exec() {
        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script");
        std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        let native = temp.path().join("native");
        std::fs::copy("/bin/true", &native).unwrap();
        let script = CheckedExecutable::for_test(&script)
            .verify_at_spawn()
            .unwrap();
        let native = CheckedExecutable::for_test(&native)
            .verify_at_spawn()
            .unwrap();
        assert!(
            script.script,
            "a #! script needs /proc/self/fd/N after exec"
        );
        assert!(!native.script, "an ELF provider keeps FD_CLOEXEC");
    }
}
