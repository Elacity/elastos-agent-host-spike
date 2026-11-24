//! Secret auth-state files and the lock files beside them.

use std::fs::File;
use std::path::Path;

#[cfg(unix)]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use std::io::{ErrorKind, Write};

use anyhow::{anyhow, Context};
use serde::Serialize;

#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
use std::path::PathBuf;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RegularFileIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mtime_secs: i64,
    pub(crate) mtime_nanos: i64,
    pub(crate) ctime_secs: i64,
    pub(crate) ctime_nanos: i64,
    pub(crate) len: u64,
}

#[cfg(unix)]
pub(crate) fn regular_file_identity_from_metadata(
    metadata: &std::fs::Metadata,
    label: &str,
) -> anyhow::Result<RegularFileIdentity> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("{label} must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(RegularFileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime_secs: metadata.mtime(),
            mtime_nanos: metadata.mtime_nsec(),
            ctime_secs: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
            len: metadata.len(),
        })
    }
}

#[cfg(not(unix))]
pub(crate) fn regular_file_identity_from_metadata(
    _metadata: &std::fs::Metadata,
    _label: &str,
) -> anyhow::Result<RegularFileIdentity> {
    Err(unsupported_on_this_platform())
}

pub(crate) fn observe_optional_regular_file_identity(
    path: &Path,
    label: &str,
) -> anyhow::Result<Option<RegularFileIdentity>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to inspect {label} {path:?}"));
        }
    };
    Ok(Some(regular_file_identity_from_metadata(&metadata, label)?))
}

#[cfg(unix)]
pub(crate) fn sync_parent_directory(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn sync_parent_directory(_path: &Path) -> anyhow::Result<()> {
    Err(unsupported_on_this_platform())
}

pub(crate) fn write_secret_json_atomic(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    write_secret_bytes_atomic(path, &serde_json::to_vec_pretty(value)?).map(|_| ())
}

pub(crate) fn write_secret_bytes_atomic(
    path: &Path,
    bytes: &[u8],
) -> anyhow::Result<Option<RegularFileIdentity>> {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("secret state path has no file name"))?;
    let temp = path.with_file_name(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        unique
    ));
    let result = (|| -> anyhow::Result<Option<RegularFileIdentity>> {
        let mut file = open_new_secret_file(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)?;
        set_secret_file_permissions(path)?;
        sync_parent_directory(path)?;
        #[cfg(test)]
        run_auth_state_write_hook(path)?;
        let held = regular_file_identity_from_metadata(&file.metadata()?, "secret state")?;
        Ok(
            (observe_optional_regular_file_identity(path, "secret state")? == Some(held))
                .then_some(held),
        )
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
pub(crate) type AuthStateWriteHook = Box<dyn FnOnce(&Path) -> anyhow::Result<()> + Send>;
#[cfg(test)]
pub(crate) static AUTH_STATE_WRITE_HOOKS: OnceLock<Mutex<HashMap<PathBuf, AuthStateWriteHook>>> =
    OnceLock::new();

#[cfg(test)]
fn run_auth_state_write_hook(path: &Path) -> anyhow::Result<()> {
    let hook = AUTH_STATE_WRITE_HOOKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .remove(path);
    if let Some(hook) = hook {
        hook(path)?;
    }
    Ok(())
}
