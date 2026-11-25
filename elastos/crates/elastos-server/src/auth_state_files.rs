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
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        anyhow::bail!("{label} lock must be a regular non-symlink file");
    }
    // The mode belongs to the inode this descriptor already holds.
    #[cfg(test)]
    before_lock_file_mode(path);
    restrict_open_file_mode(&file, 0o600)
        .with_context(|| format!("failed to restrict secret file permissions for {path:?}"))?;
    Ok(file)
}

#[cfg(not(unix))]
pub(crate) fn open_regular_lock_file(_path: &Path, _label: &str) -> anyhow::Result<File> {
    Err(unsupported_on_this_platform())
}

/// The object helper refuses these sign-in and audit records, and the
/// temporary names `write_secret_bytes_atomic` builds for them. Lock files
/// stay openable: a read still has to take the lock, and the lock is not the
/// record.
pub(crate) const OBJECT_HELPER_AUTH_WRITE_REFUSAL: &str =
    "object helper refuses to write Home sign-in files";

fn auth_sign_in_family(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name == "auth-state.json"
        || name == "audit-chain-required.json"
        || (name.starts_with(".auth-state.json.") && name.ends_with(".tmp"))
        || (name.starts_with(".audit-chain-required.json.") && name.ends_with(".tmp"))
}

/// Open `path` with `O_NOFOLLOW` and `fchmod` it to `mode` when the mode
/// differs. A symlink fails the open and its target stays as it is.
#[cfg(unix)]
pub(crate) fn restrict_nofollow_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to open {path:?} to restrict its mode"))?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!("refusing to change the mode of a symlink {path:?}");
    }
    restrict_open_file_mode(&file, mode)
        .with_context(|| format!("failed to restrict secret file permissions for {path:?}"))
}

#[cfg(all(test, unix))]
thread_local! {
    static SECRET_MODE_NARROWS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(unix)]
fn restrict_open_file_mode(file: &File, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let current = file.metadata()?.permissions().mode() & 0o777;
    if current == mode {
        return Ok(());
    }
    #[cfg(test)]
    SECRET_MODE_NARROWS.with(|count| count.set(count.get() + 1));
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .context("failed to restrict secret file permissions")
}

#[cfg(unix)]
pub(crate) fn set_secret_file_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to restrict secret file permissions for {path:?}"))?;
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("secret file must be a regular non-symlink file");
    }
    restrict_open_file_mode(&file, 0o600)
        .with_context(|| format!("failed to restrict secret file permissions for {path:?}"))
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

/// The object helper does not open the device key. On macOS the fence also
/// refuses to stat it. That refusal is an absent identity, so sign-in still
/// loads. Runtime outside the helper still sees a real permission error.
pub(crate) fn observe_device_key_for_auth_load(
    data_dir: &Path,
) -> anyhow::Result<Option<RegularFileIdentity>> {
    let path = elastos_identity::device_key_path(data_dir);
    match observe_optional_regular_file_identity(&path, "runtime device key") {
        Ok(identity) => Ok(identity),
        Err(err) if object_helper_cannot_stat_device_key(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn object_helper_cannot_stat_device_key(err: &anyhow::Error) -> bool {
    elastos_identity::object_helper_process()
        && err.chain().any(|cause| {
            cause.downcast_ref::<std::io::Error>().is_some_and(|io| {
                io.kind() == ErrorKind::PermissionDenied || io.raw_os_error() == Some(1)
            })
        })
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
    if elastos_identity::object_helper_process() && auth_sign_in_family(path) {
        anyhow::bail!(OBJECT_HELPER_AUTH_WRITE_REFUSAL);
    }
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
        #[cfg(unix)]
        set_open_secret_file_permissions(&file)?;
        #[cfg(not(unix))]
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

/// Sets mode `0600` on a descriptor the caller already holds.
#[cfg(unix)]
pub(crate) fn set_open_secret_file_permissions(file: &File) -> anyhow::Result<()> {
    restrict_open_file_mode(file, 0o600)
}

#[cfg(all(test, unix))]
thread_local! {
    static BEFORE_LOCK_FILE_MODE: std::cell::Cell<Option<fn(&Path)>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(all(test, unix))]
fn before_lock_file_mode(path: &Path) {
    BEFORE_LOCK_FILE_MODE.with(|hook| {
        if let Some(hook) = hook.take() {
            hook(path);
        }
    });
}

#[cfg(all(test, unix))]
fn clear_lock_file_mode_hook() {
    BEFORE_LOCK_FILE_MODE.with(|hook| hook.set(None));
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        clear_lock_file_mode_hook, open_regular_lock_file, set_open_secret_file_permissions,
        BEFORE_LOCK_FILE_MODE,
    };
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn descriptor_mode(file: &File) -> u32 {
        file.metadata().unwrap().permissions().mode() & 0o777
    }

    fn write_mode(path: &Path, bytes: &[u8], bits: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(bits)).unwrap();
    }

    fn swap_lock_path_for_victim(locked: &Path) {
        let victim = locked.with_file_name("victim");
        fs::remove_file(locked).unwrap();
        std::os::unix::fs::symlink(&victim, locked).unwrap();
    }

    struct ClearHook;
    impl Drop for ClearHook {
        fn drop(&mut self) {
            clear_lock_file_mode_hook();
        }
    }

    #[test]
    fn swapped_lock_path_does_not_change_the_target_mode() {
        let _clear = ClearHook;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth-state.json.lock");
        let victim = dir.path().join("victim");
        write_mode(&victim, b"victim", 0o644);
        write_mode(&path, b"lock", 0o644);
        BEFORE_LOCK_FILE_MODE.with(|hook| hook.set(Some(swap_lock_path_for_victim)));
        let file = open_regular_lock_file(&path, "auth state").unwrap();
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(mode(&victim), 0o644, "symlink target mode changed");
        assert_eq!(descriptor_mode(&file), 0o600);
    }

    #[test]
    fn open_descriptor_mode_does_not_follow_a_swapped_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        let victim = dir.path().join("victim");
        write_mode(&victim, b"victim", 0o644);
        write_mode(&path, b"secret", 0o644);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        swap_lock_path_for_victim(&path);
        set_open_secret_file_permissions(&file).unwrap();
        assert_eq!(mode(&victim), 0o644, "symlink target mode changed");
        assert_eq!(descriptor_mode(&file), 0o600);
    }

    #[test]
    fn existing_loose_lock_ends_at_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth-state.json.lock");
        write_mode(&path, b"lock", 0o666);
        open_regular_lock_file(&path, "auth state").unwrap();
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn unreadable_lock_is_refused_and_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth-state.json.lock");
        write_mode(&path, b"lock", 0o000);
        let error = open_regular_lock_file(&path, "auth state").unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("failed to open"), "{text}");
        assert!(
            error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            }),
            "{text}"
        );
        assert_eq!(mode(&path), 0o000);
    }

    #[test]
    fn unreadable_recovery_key_is_refused_and_keeps_its_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ElastOS/System/Auth/recovery-archive.key");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        write_mode(&path, &[7u8; 32], 0o000);
        let error = crate::auth::load_or_create_recovery_archive_key(dir.path()).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("failed to read"), "{text}");
        assert_eq!(mode(&path), 0o000);
    }

    #[test]
    fn secret_mode_changes_only_when_it_differs_and_a_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery-archive.key");
        let victim = dir.path().join("victim");
        write_mode(&victim, b"victim", 0o644);
        write_mode(&path, b"key", 0o644);
        super::SECRET_MODE_NARROWS.with(|count| count.set(0));
        super::set_secret_file_permissions(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(super::SECRET_MODE_NARROWS.with(|count| count.get()), 1);
        super::set_secret_file_permissions(&path).unwrap();
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            super::SECRET_MODE_NARROWS.with(|count| count.get()),
            1,
            "a matching mode does not fchmod again"
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        let error = super::set_secret_file_permissions(&path).unwrap_err();
        assert!(
            format!("{error:#}").contains("failed to restrict secret file permissions"),
            "{error:#}"
        );
        assert_eq!(mode(&victim), 0o644, "symlink target mode changed");
    }

    #[test]
    fn a_directory_narrows_through_the_open_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("folder");
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        super::restrict_nofollow_mode(&path, 0o700).unwrap();
        assert_eq!(mode(&path), 0o700);
        super::restrict_nofollow_mode(&path, 0o700).unwrap();
        assert_eq!(mode(&path), 0o700);
    }

    #[test]
    fn this_process_can_write_a_sign_in_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("auth-state.json");
        super::write_secret_bytes_atomic(&path, b"{\"ok\":true}").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"ok\":true}");
        assert!(!elastos_identity::object_helper_process());
    }
}
