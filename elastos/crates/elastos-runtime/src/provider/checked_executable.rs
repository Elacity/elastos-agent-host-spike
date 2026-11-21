//! An executable pinned by the caller's verified release metadata.
use sha2::{Digest, Sha256};
#[cfg(target_os = "macos")]
use std::io::{Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd};
use std::{
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct PreparedExecutable {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "macos")]
    _private_dir: tempfile::TempDir,
    exec_path: PathBuf,
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
}

/// The release owner supplies the signed component checksum. Runtime checks it
/// again immediately before each provider process starts.
pub struct CheckedExecutable {
    path: PathBuf,
    digest: [u8; 32],
    refusal: Option<String>,
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
        })
    }

    pub fn refused(path: &Path, reason: String) -> Self {
        Self {
            path: path.to_path_buf(),
            digest: [0; 32],
            refusal: Some(reason),
        }
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
            Ok(PreparedExecutable {
                file: unsafe { std::fs::File::from_raw_fd(fd) },
                exec_path: format!("/proc/self/fd/{fd}").into(),
            })
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let private_dir = tempfile::Builder::new()
                .prefix("elastos-provider-")
                .tempdir()
                .map_err(|e| format!("provider executable copy cannot be created: {e}"))?;
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
            Ok(PreparedExecutable {
                _private_dir: private_dir,
                exec_path,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err("provider executable execution is unsupported on this OS".into())
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
        }
    }
}
