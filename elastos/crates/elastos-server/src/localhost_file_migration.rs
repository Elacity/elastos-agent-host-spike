//! The localhost file-key walker.
//!
//! Before the localhost provider starts, every envelope under the five
//! encrypted roots is rewritten onto the HKDF file key derived from the
//! device key, and the marker `identity/localhost-file-key-v1` records the
//! finished migration. The marker counts as finished only when it carries the
//! fixed record written by the migration; any other content stops local apps.

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
const LOCALHOST_MIGRATION_RECORD: &[u8] = b"elastos-localhost-file-v1\n";
#[cfg(unix)]
const LOCALHOST_REWRITE_SUFFIX: &str = ".elastos-localhost-file-key-v1.tmp";
/// Local-app roots whose files are sealed. `MyWebSite` and `Public` stay
/// plaintext. `identity/` and `did/` are not in this list.
#[cfg(unix)]
const LOCALHOST_ENCRYPTED_ROOTS: &[&str] = &["AppCapsules", "ElastOS", "Local", "Users", "UsersAI"];

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
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    let dir = std::fs::File::open(parent)?;
    dir.sync_all()?;
    Ok(())
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

/// Rewrite one envelope onto the file key.
///
/// A file that is not the JSON envelope is left as it is. An envelope that
/// opens with the raw device key is sealed again under the file key. An
/// envelope that opens only with the file key was written by an earlier pass
/// that crashed before the marker; it is left as it is. Any other envelope
/// stops local apps and is not written.
#[cfg(unix)]
fn migrate_localhost_envelope(
    path: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<()> {
    let bytes = read_nofollow(path).with_context(|| localhost_refused(path, "cannot be read"))?;
    if !localhost_provider::is_encrypted_envelope(&bytes) {
        return Ok(());
    }
    if let Ok(plaintext) = localhost_provider::decrypt_bytes(device_key, &bytes) {
        let sealed = localhost_provider::encrypt_bytes(file_key, &plaintext)
            .with_context(|| localhost_refused(path, "cannot be sealed"))?;
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
fn migrate_localhost_tree(
    dir: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).with_context(|| localhost_refused(dir, "cannot be read"))? {
        let entry = entry.with_context(|| localhost_refused(dir, "cannot be read"))?;
        names.push(entry.file_name());
    }
    names.sort();
    let suffix = LOCALHOST_REWRITE_SUFFIX.as_bytes();
    for name in names {
        let path = dir.join(&name);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| localhost_refused(&path, "cannot be read"))?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return Err(localhost_refused(&path, "is a link"));
        }
        let name_bytes = name.as_bytes();
        if file_type.is_file() && name_bytes.starts_with(b".") && name_bytes.ends_with(suffix) {
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
fn write_localhost_marker(marker: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let identity = marker.parent().ok_or_else(|| {
        anyhow::anyhow!("localhost file key marker has no directory; local apps were not started")
    })?;
    match std::fs::symlink_metadata(identity) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(localhost_refused(identity, "is a link"));
        }
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => return Err(localhost_refused(identity, "is not a directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(identity)
                .with_context(|| localhost_refused(identity, "cannot be created"))?;
            std::fs::set_permissions(identity, std::fs::Permissions::from_mode(0o700))
                .with_context(|| localhost_refused(identity, "cannot be created"))?;
        }
        Err(err) => {
            return Err(err).with_context(|| localhost_refused(identity, "cannot be read"));
        }
    }
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
