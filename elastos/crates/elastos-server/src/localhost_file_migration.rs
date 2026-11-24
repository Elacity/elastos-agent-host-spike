//! The localhost file-key walker.
//!
//! Before the localhost provider starts, every envelope under the five
//! encrypted roots is rewritten onto the HKDF file key derived from the
//! device key, and the marker `identity/localhost-file-key-v1` records the
//! finished migration. The marker counts as finished only when it carries the
//! fixed record written by the migration; any other content stops local apps.
//!
//! One lock on `identity/localhost-file-key.lock` covers the walk, so two
//! Homes on one data folder take turns. Each new envelope is written to a
//! temp file in the same directory, fsynced, and renamed. A crash at any of
//! those writes leaves the previous bytes or the new bytes. The next start
//! finishes the walk. A finished file opens with the file key only.
//!
//! A symlink or a hard link stops the walk. A file that changes while the
//! walk is reading it stops the walk and keeps the new bytes. After the
//! marker is the fixed record, the raw device key is not used to open or
//! rewrite local-app files.
//!
//! An older build still passes that raw device key to the helper and does not
//! read the marker. Rewritten files then fail to open. Files that older build
//! writes afterwards stay under the device key. A later start of this build
//! does not rewrite them, because the marker is already present. The helper
//! has only the file key, so those later files fail to open too. Start itself
//! still proceeds, because the walk is skipped.

use std::path::Path;

#[cfg(unix)]
use anyhow::Context as _;
use elastos_common::localhost::file_backed_prefixes;
use elastos_runtime::provider;

#[cfg(unix)]
const LOCALHOST_FILE_KEY_INFO: &[u8] = b"elastos-localhost-file-v1";
#[cfg(unix)]
const LOCALHOST_MIGRATION_MARKER: &str = "localhost-file-key-v1";
#[cfg(unix)]
const LOCALHOST_MIGRATION_LOCK: &str = "localhost-file-key.lock";
#[cfg(unix)]
const LOCALHOST_MIGRATION_RECORD: &[u8] = b"elastos-localhost-file-v1\n";
#[cfg(unix)]
const LOCALHOST_REWRITE_SUFFIX: &str = ".elastos-localhost-file-key-v1.tmp";
/// Local-app roots whose files are sealed. `MyWebSite` and `Public` stay
/// plaintext. `identity/` and `did/` are not in this list.
#[cfg(unix)]
const LOCALHOST_ENCRYPTED_ROOTS: &[&str] = &["AppCapsules", "ElastOS", "Local", "Users", "UsersAI"];

#[cfg(all(unix, test))]
type MigrationReplaceHook = Box<dyn Fn(&Path)>;

#[cfg(all(unix, test))]
thread_local! {
    static WRITE_BUDGET: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    static BEFORE_REPLACE: std::cell::RefCell<Option<MigrationReplaceHook>> =
        std::cell::RefCell::new(None);
}

/// Stops the walk after this many migration writes. `None` writes normally.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_write_budget(budget: Option<u32>) {
    WRITE_BUDGET.with(|slot| slot.set(budget));
}

/// Runs once for each file, after the bytes are read and before they are
/// replaced. The test uses this to change the file mid-walk.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_before_replace(hook: Option<MigrationReplaceHook>) {
    BEFORE_REPLACE.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(all(unix, test))]
fn charge_migration_write() -> anyhow::Result<()> {
    WRITE_BUDGET.with(|budget| {
        let Some(left) = budget.get() else {
            return Ok(());
        };
        if left == 0 {
            return Err(anyhow::anyhow!(
                "localhost file migration stopped at a write; local apps were not started"
            ));
        }
        budget.set(Some(left - 1));
        Ok(())
    })
}

#[cfg(all(unix, not(test)))]
fn charge_migration_write() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(all(unix, test))]
fn run_before_replace(path: &Path) {
    let hook = BEFORE_REPLACE.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        BEFORE_REPLACE.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(all(unix, not(test)))]
fn run_before_replace(_path: &Path) {}

#[cfg(unix)]
fn localhost_refused(path: &Path, why: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "localhost file {} {why}; local apps were not started",
        path.display()
    )
}

/// HKDF-SHA256 file key for localhost envelopes.
///
/// `ikm` is the device key, salt is empty, and info is
/// `elastos-localhost-file-v1`. The provider uses these 32 bytes as AES-256,
/// with no further expansion.
#[cfg(unix)]
pub(crate) fn localhost_file_key(device_key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, device_key);
    let mut okm = [0u8; 32];
    hk.expand(LOCALHOST_FILE_KEY_INFO, &mut okm)
        .map_err(|_| anyhow::anyhow!("localhost file key expansion failed"))?;
    Ok(okm)
}

/// Holds the exclusive migration lock until dropped.
#[cfg(unix)]
pub(crate) struct LocalhostMigrationLock {
    _file: std::fs::File,
}

#[cfg(all(unix, test))]
pub(crate) fn hold_localhost_migration_lock(
    data_dir: &Path,
) -> anyhow::Result<LocalhostMigrationLock> {
    acquire_migration_lock(data_dir)
}

/// Write `bytes` by creating a temp file in the same directory, calling
/// `fsync`, then `rename` over `path`. A crash keeps the previous bytes.
#[cfg(unix)]
fn replace_file_fsync_rename(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "localhost file has no directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "localhost file has no name",
        )
    })?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(file_name);
    tmp_name.push(LOCALHOST_REWRITE_SUFFIX);
    let tmp = parent.join(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    charge_migration_write().map_err(io_error)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    if let Err(err) = (|| {
        charge_migration_write().map_err(io_error)?;
        file.write_all(bytes)?;
        charge_migration_write().map_err(io_error)?;
        file.sync_all()?;
        Ok(())
    })() {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);
    charge_migration_write().map_err(io_error)?;
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    charge_migration_write().map_err(io_error)?;
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn io_error(err: anyhow::Error) -> std::io::Error {
    std::io::Error::other(err)
}

#[cfg(unix)]
fn read_nofollow(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
fn is_rewrite_temp(name: &std::ffi::OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    let bytes = name.as_bytes();
    bytes.starts_with(b".") && bytes.ends_with(LOCALHOST_REWRITE_SUFFIX.as_bytes())
}

#[cfg(unix)]
fn opened_file_still_matches(
    path: &Path,
    file: &std::fs::File,
    read_len: u64,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let open_meta = file
        .metadata()
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    let path_meta = std::fs::symlink_metadata(path)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    if path_meta.file_type().is_symlink() {
        return Err(localhost_refused(path, "is a link"));
    }
    if !path_meta.is_file()
        || path_meta.nlink() != 1
        || open_meta.nlink() != 1
        || path_meta.dev() != open_meta.dev()
        || path_meta.ino() != open_meta.ino()
        || path_meta.len() != read_len
        || open_meta.len() != read_len
    {
        return Err(localhost_refused(path, "changed while it was being read"));
    }
    Ok(())
}

/// Rewrite one envelope onto the file key.
///
/// A file that is not the JSON envelope is left as it is. An envelope that
/// opens with the raw device key is sealed again under the file key. An
/// envelope that opens only with the file key was written by an earlier pass
/// that crashed before the marker; it is left as it is. Any other envelope
/// stops local apps and is not written. A file that changes after it is read
/// is not written either.
#[cfg(unix)]
fn migrate_localhost_envelope(
    path: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    let meta = file
        .metadata()
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    if !meta.is_file() {
        return Err(localhost_refused(path, "is not a regular file"));
    }
    if meta.nlink() > 1 {
        return Err(localhost_refused(path, "is linked from another path"));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    run_before_replace(path);
    opened_file_still_matches(path, &file, bytes.len() as u64)?;
    if !localhost_provider::is_encrypted_envelope(&bytes) {
        return Ok(());
    }
    if let Ok(plaintext) = localhost_provider::decrypt_bytes(device_key, &bytes) {
        let sealed = localhost_provider::encrypt_bytes(file_key, &plaintext)
            .with_context(|| localhost_refused(path, "cannot be sealed"))?;
        opened_file_still_matches(path, &file, bytes.len() as u64)?;
        replace_file_fsync_rename(path, &sealed)
            .with_context(|| localhost_refused(path, "cannot be replaced"))?;
        return Ok(());
    }
    // The file key recognizes a file already replaced. The raw device key is
    // not tried again after the file key fails, and it is not a fallback once
    // the marker says migration finished.
    if localhost_provider::decrypt_bytes(file_key, &bytes).is_ok() {
        return Ok(());
    }
    Err(localhost_refused(path, "does not decrypt"))
}

#[cfg(unix)]
fn without_rewrite_temps(names: &[std::ffi::OsString]) -> Vec<std::ffi::OsString> {
    names
        .iter()
        .filter(|name| !is_rewrite_temp(name))
        .cloned()
        .collect()
}

#[cfg(unix)]
fn directory_names(dir: &Path) -> anyhow::Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| localhost_refused(dir, "cannot be read"))? {
        let entry = entry.with_context(|| localhost_refused(dir, "cannot be read"))?;
        names.push(entry.file_name());
    }
    names.sort();
    Ok(names)
}

#[cfg(unix)]
fn migrate_localhost_tree(
    dir: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<()> {
    let names = directory_names(dir)?;
    for name in &names {
        let path = dir.join(name);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| localhost_refused(&path, "cannot be read"))?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return Err(localhost_refused(&path, "is a link"));
        }
        if file_type.is_file() && is_rewrite_temp(name) {
            charge_migration_write()?;
            std::fs::remove_file(&path)
                .with_context(|| localhost_refused(&path, "cannot be removed"))?;
            continue;
        }
        if file_type.is_dir() {
            migrate_localhost_tree(&path, device_key, file_key)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(localhost_refused(&path, "is not a regular file"));
        }
        if std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
            return Err(localhost_refused(&path, "is linked from another path"));
        }
        migrate_localhost_envelope(&path, device_key, file_key)?;
    }
    let again = directory_names(dir)?;
    if without_rewrite_temps(&names) != without_rewrite_temps(&again) {
        return Err(localhost_refused(dir, "changed while it was being read"));
    }
    Ok(())
}

/// The marker says migration finished only when it is a regular file carrying
/// the fixed record the migration writes. A marker with any other content
/// stops local apps: the walk cannot know which key sealed the files, so it
/// must neither skip the migration nor fall back to the raw device key.
#[cfg(unix)]
fn localhost_marker_finished(marker: &Path) -> anyhow::Result<bool> {
    match std::fs::symlink_metadata(marker) {
        Ok(meta) if meta.file_type().is_symlink() => Err(localhost_refused(marker, "is a link")),
        Ok(meta) if meta.is_file() => {
            let bytes = read_nofollow(marker)
                .with_context(|| localhost_refused(marker, "cannot be read"))?;
            if bytes == LOCALHOST_MIGRATION_RECORD {
                Ok(true)
            } else {
                Err(localhost_refused(
                    marker,
                    "does not carry the migration record",
                ))
            }
        }
        Ok(_) => Err(localhost_refused(marker, "is not a file")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| localhost_refused(marker, "cannot be read")),
    }
}

#[cfg(unix)]
fn ensure_identity_dir(identity: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::symlink_metadata(identity) {
        Ok(meta) if meta.file_type().is_symlink() => Err(localhost_refused(identity, "is a link")),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(localhost_refused(identity, "is not a directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            charge_migration_write()?;
            match std::fs::DirBuilder::new().mode(0o700).create(identity) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    match std::fs::symlink_metadata(identity) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            Err(localhost_refused(identity, "is a link"))
                        }
                        Ok(meta) if meta.is_dir() => Ok(()),
                        Ok(_) => Err(localhost_refused(identity, "is not a directory")),
                        Err(err) => {
                            Err(err).with_context(|| localhost_refused(identity, "cannot be read"))
                        }
                    }
                }
                Err(err) => {
                    Err(err).with_context(|| localhost_refused(identity, "cannot be created"))
                }
            }
        }
        Err(err) => Err(err).with_context(|| localhost_refused(identity, "cannot be read")),
    }
}

#[cfg(unix)]
fn acquire_migration_lock(data_dir: &Path) -> anyhow::Result<LocalhostMigrationLock> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let identity = data_dir.join("identity");
    ensure_identity_dir(&identity)?;
    let lock_path = identity.join(LOCALHOST_MIGRATION_LOCK);
    if let Ok(meta) = std::fs::symlink_metadata(&lock_path) {
        if meta.file_type().is_symlink() {
            return Err(localhost_refused(&lock_path, "is a link"));
        }
        if !meta.is_file() {
            return Err(localhost_refused(&lock_path, "is not a file"));
        }
    }
    charge_migration_write()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| localhost_refused(&lock_path, "cannot be locked"))?;
    let meta = file
        .metadata()
        .with_context(|| localhost_refused(&lock_path, "cannot be locked"))?;
    if !meta.is_file() || meta.nlink() > 1 {
        return Err(localhost_refused(&lock_path, "is linked from another path"));
    }
    file.lock()
        .with_context(|| localhost_refused(&lock_path, "cannot be locked"))?;
    Ok(LocalhostMigrationLock { _file: file })
}

#[cfg(unix)]
fn write_localhost_marker(marker: &Path) -> anyhow::Result<()> {
    let identity = marker.parent().ok_or_else(|| {
        anyhow::anyhow!("localhost file key marker has no directory; local apps were not started")
    })?;
    ensure_identity_dir(identity)?;
    replace_file_fsync_rename(marker, LOCALHOST_MIGRATION_RECORD)
        .with_context(|| localhost_refused(marker, "cannot be replaced"))?;
    Ok(())
}

/// Rewrite local-app envelopes under the five encrypted roots onto the file key.
///
/// When `identity/localhost-file-key-v1` is a regular file carrying the fixed
/// migration record, migration has finished. This returns without reading
/// those roots and without opening any file with the raw device key. A marker
/// holding any other content is an error. The raw device key is never a
/// fallback after that marker exists.
#[cfg(unix)]
fn migrate_localhost_files_to_file_key(
    data_dir: &Path,
    device_key: &[u8; 32],
) -> anyhow::Result<()> {
    let _lock = acquire_migration_lock(data_dir)?;
    let marker = data_dir.join("identity").join(LOCALHOST_MIGRATION_MARKER);
    if localhost_marker_finished(&marker)? {
        return Ok(());
    }
    let file_key = zeroize::Zeroizing::new(localhost_file_key(device_key)?);
    for root in LOCALHOST_ENCRYPTED_ROOTS {
        let path = data_dir.join(root);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(localhost_refused(&path, "is a link"));
            }
            Ok(meta) if meta.is_dir() => {
                migrate_localhost_tree(&path, device_key, &file_key)?;
            }
            Ok(_) => return Err(localhost_refused(&path, "is not a directory")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| localhost_refused(&path, "cannot be read"));
            }
        }
    }
    write_localhost_marker(&marker)
}

/// Localhost-provider init config.
///
/// On Unix, files under the five encrypted roots are rewritten onto the HKDF
/// file key before this returns. The encryption field is that file key.
/// On Windows, files are not rewritten and the field stays the device key.
///
/// The local below is the authority-census needle for the row
/// `elastos-server/src/localhost_file_migration.rs` /
/// `localhost_provider_bridge_config` / `encryption_key: device_key_hex`
/// in `home_held_authority`. On Unix the value is the file key, not the raw
/// device key.
pub(crate) fn localhost_provider_bridge_config(
    data_dir: &Path,
    device_key: &[u8; 32],
) -> anyhow::Result<provider::BridgeProviderConfig> {
    #[cfg(unix)]
    let device_key_hex = {
        use zeroize::Zeroize;
        migrate_localhost_files_to_file_key(data_dir, device_key)?;
        let mut file_key = localhost_file_key(device_key)?;
        let file_key_hex = hex::encode(file_key);
        file_key.zeroize();
        file_key_hex
    };
    #[cfg(not(unix))]
    let device_key_hex = hex::encode(device_key);
    Ok(provider::BridgeProviderConfig {
        base_path: data_dir.to_string_lossy().to_string(),
        allowed_paths: file_backed_prefixes(),
        read_only: false,
        encryption_key: device_key_hex,
        ..Default::default()
    })
}
