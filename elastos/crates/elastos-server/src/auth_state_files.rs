//! Secret auth-state files and the lock files beside them.

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(unix)]
use anyhow::{anyhow, Context};

#[cfg(not(unix))]
fn unsupported_on_this_platform() -> anyhow::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "unsupported on this platform",
    )
    .into()
}

#[cfg(unix)]
pub(crate) fn open_new_secret_file(path: &Path) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .with_context(|| format!("failed to create secret state file {path:?}"))
}

#[cfg(not(unix))]
pub(crate) fn open_new_secret_file(_path: &Path) -> anyhow::Result<File> {
    Err(unsupported_on_this_platform())
}

#[cfg(unix)]
pub(crate) fn ensure_regular_auth_parent(data_dir: &Path, parent: &Path) -> anyhow::Result<()> {
    let relative = parent
        .strip_prefix(data_dir)
        .map_err(|_| anyhow!("auth state path escaped its data root"))?;
    let mut current = data_dir.to_path_buf();
    for component in relative.components() {
        current.push(component);
        let metadata = match std::fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                std::fs::create_dir(&current)
                    .with_context(|| format!("failed to create auth state path {current:?}"))?;
                std::fs::symlink_metadata(&current).with_context(|| {
                    format!("failed to inspect created auth state path {current:?}")
                })?
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("failed to inspect auth state path {current:?}"));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("auth state path must use regular non-symlink directories");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn ensure_regular_auth_parent(_data_dir: &Path, _parent: &Path) -> anyhow::Result<()> {
    Err(unsupported_on_this_platform())
}

#[cfg(unix)]
pub(crate) fn open_regular_lock_file(path: &Path, label: &str) -> anyhow::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {label} lock {path:?}"))?;
    if !file.metadata()?.is_file() {
        anyhow::bail!("{label} lock must be a regular non-symlink file");
    }
    set_secret_file_permissions(path)?;
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open_regular_lock_file(_path: &Path, _label: &str) -> anyhow::Result<File> {
    Err(unsupported_on_this_platform())
}

#[cfg(unix)]
pub(crate) fn set_secret_file_permissions(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to restrict secret file permissions for {path:?}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_secret_file_permissions(_path: &Path) -> anyhow::Result<()> {
    Err(unsupported_on_this_platform())
}
