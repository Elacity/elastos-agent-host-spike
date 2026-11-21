//! An executable pinned by the caller's verified release metadata.
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

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

    pub fn verify_at_spawn(&self) -> Result<(), String> {
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
        Ok(())
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
