//! Rootfs caching and overlay management

use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::{fs, io, io::Seek, io::Write};

use elastos_common::{ElastosError, Result};

/// Manages rootfs images and overlays
pub struct RootfsManager {
    /// Directory for cached rootfs images
    cache_dir: PathBuf,

    /// Directory for VM-specific overlays
    overlay_dir: PathBuf,
}

impl RootfsManager {
    /// Create a new rootfs manager
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        let cache_dir = cache_dir.into();
        let overlay_dir = cache_dir.join("overlays");

        Self {
            cache_dir,
            overlay_dir,
        }
    }

    /// Initialize the rootfs manager (create directories)
    pub async fn init(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.cache_dir)
            .await
            .map_err(|e| ElastosError::Storage(format!("Failed to create cache dir: {}", e)))?;

        tokio::fs::create_dir_all(&self.overlay_dir)
            .await
            .map_err(|e| ElastosError::Storage(format!("Failed to create overlay dir: {}", e)))?;

        Ok(())
    }

    /// Copy exactly the verified descriptor into a new writable overlay.
    pub async fn create_verified_overlay(
        &self,
        vm_id: &str,
        image: &fs::File,
        source: &Path,
        expected_sha256: &str,
    ) -> Result<(PathBuf, fs::File)> {
        let overlay_path = self.overlay_dir.join(format!("{}.ext4", vm_id));
        let mut input = image
            .try_clone()
            .map_err(|e| ElastosError::Storage(e.to_string()))?;
        let source = source.to_path_buf();
        let expected_sha256 = expected_sha256.to_owned();
        let output = overlay_path.clone();
        let file = tokio::task::spawn_blocking(move || -> Result<fs::File> {
            input
                .rewind()
                .map_err(|e| ElastosError::Storage(e.to_string()))?;
            let mut target = open_anonymous_overlay(&output).map_err(|e| {
                ElastosError::Storage(format!(
                    "Stale VM overlay refused or anonymous disk unavailable: {e}"
                ))
            })?;
            let copied = (|| -> io::Result<()> {
                let mut hash = Sha256::new();
                let mut chunk = [0; 64 * 1024];
                loop {
                    let count = io::Read::read(&mut input, &mut chunk)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&chunk[..count]);
                    target.write_all(&chunk[..count])?;
                }
                if format!("{:x}", hash.finalize()) != expected_sha256 {
                    return Err(io::Error::other(
                        "Changed VM image refused: SHA-256/CID differs from signed entry",
                    ));
                }
                let opened = input.metadata()?;
                let selected = fs::symlink_metadata(&source)?;
                if !selected.file_type().is_file()
                    || opened.dev() != selected.dev()
                    || opened.ino() != selected.ino()
                {
                    return Err(io::Error::other(
                        "VM image path replaced after verification",
                    ));
                }
                target.sync_all()
            })();
            copied.map_err(|e| ElastosError::Storage(e.to_string()))?;
            Ok(target)
        })
        .await
        .map_err(|e| ElastosError::Storage(e.to_string()))??;
        Ok((overlay_path, file))
    }

    /// Get or create a persistent data disk for a capsule.
    ///
    /// The disk is a sparse ext4 file that survives VM restarts.
    /// Stored in `{cache_dir}/data-disks/{capsule_name}-data.ext4`.
    pub async fn get_or_create_data_disk(
        &self,
        capsule_name: &str,
        size_mb: u32,
    ) -> Result<PathBuf> {
        let data_dir = self.cache_dir.join("data-disks");
        tokio::fs::create_dir_all(&data_dir).await.map_err(|e| {
            ElastosError::Storage(format!("Failed to create data-disks dir: {}", e))
        })?;

        let disk_path = data_dir.join(format!("{}-data.ext4", capsule_name));

        if disk_path.exists() {
            tracing::info!(
                "Reusing existing data disk: {} ({}MB)",
                disk_path.display(),
                size_mb
            );
            return Ok(disk_path);
        }

        tracing::info!(
            "Creating data disk for '{}': {} ({}MB sparse)",
            capsule_name,
            disk_path.display(),
            size_mb
        );

        // Create sparse file with truncate
        let size_bytes = (size_mb as u64) * 1024 * 1024;
        let file = tokio::fs::File::create(&disk_path)
            .await
            .map_err(|e| ElastosError::Storage(format!("Failed to create data disk: {}", e)))?;
        file.set_len(size_bytes)
            .await
            .map_err(|e| ElastosError::Storage(format!("Failed to set data disk size: {}", e)))?;
        drop(file);

        // Format as ext4
        let output = tokio::process::Command::new("mkfs.ext4")
            .args(["-F", "-q"])
            .arg(&disk_path)
            .output()
            .await
            .map_err(|e| ElastosError::Storage(format!("Failed to run mkfs.ext4: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Clean up failed disk
            let _ = tokio::fs::remove_file(&disk_path).await;
            return Err(ElastosError::Storage(format!(
                "mkfs.ext4 failed: {}",
                stderr
            )));
        }

        Ok(disk_path)
    }

    /// Get the cache directory path
    #[cfg(test)]
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Get the overlay directory path
    #[cfg(test)]
    pub fn overlay_dir(&self) -> &Path {
        &self.overlay_dir
    }
}

fn open_anonymous_overlay(path: &Path) -> io::Result<fs::File> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "overlay exists",
        ));
    }
    open_private_file(path.parent().unwrap())
}

/// Open an unnamed file in `directory`.
///
/// Linux uses `O_TMPFILE`. Other hosts use an unlinked temporary file. The
/// file has no directory entry, so a later write to a named file in
/// `directory` cannot change the bytes this descriptor reads.
pub fn open_private_file(directory: &Path) -> io::Result<fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let dir = fs::File::open(directory)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` is a new descriptor from `openat`, or we already returned.
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        tempfile::tempfile_in(directory)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_rootfs_manager_init() {
        let temp = tempdir().unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));

        manager.init().await.unwrap();

        assert!(manager.cache_dir().exists());
        assert!(manager.overlay_dir().exists());
    }

    #[tokio::test]
    async fn verified_overlay_matches_open_image_and_refuses_change() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("rootfs.ext4");
        fs::write(&source, b"signed image").unwrap();
        let image = fs::File::open(&source).unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));
        manager.init().await.unwrap();
        let digest = format!("{:x}", Sha256::digest(b"signed image"));
        let (overlay, mut file) = manager
            .create_verified_overlay("valid", &image, &source, &digest)
            .await
            .unwrap();
        assert!(!overlay.exists());
        file.rewind().unwrap();
        let mut checked = Vec::new();
        io::Read::read_to_end(&mut file, &mut checked).unwrap();
        assert_eq!(checked, b"signed image");
        fs::write(&source, b"other  image").unwrap();
        assert!(manager
            .create_verified_overlay("changed", &image, &source, &digest)
            .await
            .unwrap_err()
            .to_string()
            .contains("Changed VM image refused"));
        assert!(!manager.overlay_dir().join("changed.ext4").exists());
    }

    #[tokio::test]
    async fn verified_overlay_refuses_stale_file() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("rootfs.ext4");
        fs::write(&source, b"signed image").unwrap();
        let image = fs::File::open(&source).unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));
        manager.init().await.unwrap();
        fs::write(manager.overlay_dir().join("stale.ext4"), b"old").unwrap();
        let digest = format!("{:x}", Sha256::digest(b"signed image"));
        assert!(manager
            .create_verified_overlay("stale", &image, &source, &digest)
            .await
            .unwrap_err()
            .to_string()
            .contains("Stale VM overlay refused"));
        assert_eq!(
            fs::read(manager.overlay_dir().join("stale.ext4")).unwrap(),
            b"old"
        );
    }

    #[tokio::test]
    async fn swapped_overlay_path_cannot_change_boot_disk() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("rootfs.ext4");
        fs::write(&source, b"signed image").unwrap();
        let image = fs::File::open(&source).unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));
        manager.init().await.unwrap();
        let digest = format!("{:x}", Sha256::digest(b"signed image"));
        let (overlay, mut file) = manager
            .create_verified_overlay("swapped", &image, &source, &digest)
            .await
            .unwrap();
        fs::write(&overlay, b"attacker data").unwrap();
        file.rewind().unwrap();
        let mut boot_disk = Vec::new();
        io::Read::read_to_end(&mut file, &mut boot_disk).unwrap();
        assert_eq!(
            boot_disk, b"signed image",
            "path swap changed the boot disk"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verified_overlay_refuses_replaced_source() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("rootfs.ext4");
        fs::write(&source, b"signed image").unwrap();
        let image = fs::File::open(&source).unwrap();
        fs::rename(&source, temp.path().join("old.ext4")).unwrap();
        fs::write(&source, b"signed image").unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));
        manager.init().await.unwrap();
        let digest = format!("{:x}", Sha256::digest(b"signed image"));
        assert!(manager
            .create_verified_overlay("replaced", &image, &source, &digest)
            .await
            .unwrap_err()
            .to_string()
            .contains("path replaced"));
        assert!(!manager.overlay_dir().join("replaced.ext4").exists());
    }

    #[tokio::test]
    async fn test_data_disk_creation() {
        if std::process::Command::new("mkfs.ext4")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("skipping data disk creation test: mkfs.ext4 unavailable");
            return;
        }
        let temp = tempdir().unwrap();
        let manager = RootfsManager::new(temp.path().join("cache"));
        manager.init().await.unwrap();

        let disk_path = manager
            .get_or_create_data_disk("test-capsule", 16)
            .await
            .unwrap();

        // Verify file exists at expected path
        assert!(disk_path.exists());
        assert_eq!(
            disk_path,
            temp.path().join("cache/data-disks/test-capsule-data.ext4")
        );

        // Verify sparse file (logical size = 16MB)
        let metadata = std::fs::metadata(&disk_path).unwrap();
        assert_eq!(metadata.len(), 16 * 1024 * 1024);

        // Calling again reuses existing disk
        let disk_path2 = manager
            .get_or_create_data_disk("test-capsule", 16)
            .await
            .unwrap();
        assert_eq!(disk_path, disk_path2);
    }
}
