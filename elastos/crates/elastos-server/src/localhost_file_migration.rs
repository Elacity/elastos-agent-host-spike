//! The localhost file-key walker.
//!
//! A migration problem does not stop Home (`api/routes.rs` `health`,
//! `api/server.rs` `ServeDir`). The helper stays down, including `MyWebSite`
//! and `Public`, and every localhost route refuses with one sentence: the
//! relative path, the cause, and what to do. Nothing starts unfenced.
//!
//! `identity/localhost-file-key-v1` is format `1` plus
//! SHA-256(`elastos-localhost-file-key-fingerprint-v1\0` || file key). A
//! different fingerprint leaves files untouched (restored or copied folder,
//! changed device key). A matching marker still walks, so an older build's
//! later device-key file is rewritten. A file is an envelope only when
//! `is_encrypted_envelope` accepts it, in any field order. The walk does not
//! skip on a fixed prefix. A file larger than 32 MiB is read only for a short
//! header. If that header cannot start an envelope, the file is left alone,
//! whatever its size. If it can, the file is refused by name and its body is
//! not read. The cap is for envelopes. The walk logs a count every few seconds. A waiter on
//! `identity/localhost-file-key.lock` logs that. The walk runs only from
//! `setup_server_infrastructure` (`spawn_host_providers`). `elastos serve`
//! takes `host_lock.rs` `acquire_host_process_lock` before that
//! (`serve_cmd.rs` `run_serve`) and skips the lock when
//! `ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1`. `elastos gateway`, including
//! its public mode, and `elastos home --browser` also take that lock
//! (`gateway_cmd.rs`). A second one of these stops with "another ElastOS
//! host already owns". Gateway and `home --browser` call
//! `setup_gateway_infrastructure` or `setup_control_plane_infrastructure`
//! (`spawn_host_providers` is false), so they do not walk. Update and the
//! provider host take the same lock and do not run this walk. `elastos run`
//! of a data capsule calls `serve_web_capsule` (`main.rs`), which walks and
//! does not take the host lock. `elastos capsule` attaches to a running
//! runtime and does not walk. `elastos run` and a host can therefore overlap.
//! They cannot mix keys: the file key is HKDF-SHA256 of the device key (info
//! `elastos-localhost-file-v1`), and the migration lock lets one walk write
//! at a time.
//! `two_homes_on_one_data_folder_finish_on_one_key` runs two processes on one
//! folder and both finish on that same file key. A helper already running in
//! the other process is not stopped. A new inode keeps a mode that is a subset
//! of `0600`, else `0600`, and drops ACLs and extended attributes. Plaintext is
//! zeroized. The inode is checked again after the temporary file is synced and
//! before `rename`. After that check returns and before `rename` returns, a
//! same-user swap can still replace the file. This platform has no
//! inode-conditional rename.

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
#[cfg(unix)]
const LOCALHOST_ENVELOPE_LIMIT: u64 = 32 * 1024 * 1024;
#[cfg(unix)]
const ENVELOPE_HEADER: usize = 64;
#[cfg(unix)]
const RECOVERY: &str = "Make it readable or move it out of the folder, then restart.";
#[cfg(unix)]
const FINGERPRINT_DOMAIN: &[u8] = b"elastos-localhost-file-key-fingerprint-v1\0";
/// Local-app roots whose files are sealed. `MyWebSite` and `Public` stay
/// plaintext. `identity/` and `did/` are not in this list.
#[cfg(unix)]
const LOCALHOST_ENCRYPTED_ROOTS: &[&str] = &["AppCapsules", "ElastOS", "Local", "Users", "UsersAI"];

#[cfg(all(unix, test))]
type MigrationReplaceHook = Box<dyn Fn(&Path)>;

#[cfg(all(unix, test))]
thread_local! {
    static WRITE_BUDGET: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
    static WRITE_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static BEFORE_REPLACE: std::cell::RefCell<Option<MigrationReplaceHook>> =
        std::cell::RefCell::new(None);
    static BEFORE_RENAME: std::cell::RefCell<Option<MigrationReplaceHook>> =
        std::cell::RefCell::new(None);
    static PROGRESS_LINES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Stops the walk after this many migration writes. `None` writes normally.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_write_budget(budget: Option<u32>) {
    WRITE_BUDGET.with(|slot| slot.set(budget));
}

/// The next rewrite reports this raw OS code instead of writing. The test
/// uses it for a full disk. The code stays set until the test clears it.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_write_error(code: Option<i32>) {
    WRITE_ERROR.with(|slot| slot.set(code));
}

/// Runs once for each file, after the bytes are read and before they are
/// replaced. The test uses this to change the file mid-walk.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_before_replace(hook: Option<MigrationReplaceHook>) {
    BEFORE_REPLACE.with(|slot| *slot.borrow_mut() = hook);
}

/// Runs after the temporary file is synced and before `rename`.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_before_rename(hook: Option<MigrationReplaceHook>) {
    BEFORE_RENAME.with(|slot| *slot.borrow_mut() = hook);
}

#[cfg(all(unix, test))]
pub(crate) fn take_localhost_migration_progress_lines() -> Vec<String> {
    PROGRESS_LINES.with(|slot| std::mem::take(&mut *slot.borrow_mut()))
}

#[cfg(all(unix, test))]
fn charge_migration_write() -> anyhow::Result<()> {
    WRITE_BUDGET.with(|budget| {
        let Some(left) = budget.get() else {
            return Ok(());
        };
        if left == 0 {
            return Err(anyhow::anyhow!(
                "localhost file migration stopped at a write; local apps stayed off"
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
fn injected_write_error() -> Option<std::io::Error> {
    WRITE_ERROR.with(|slot| slot.get().map(std::io::Error::from_raw_os_error))
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

#[cfg(all(unix, test))]
fn run_before_rename(path: &Path) {
    let hook = BEFORE_RENAME.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook(path);
        BEFORE_RENAME.with(|slot| *slot.borrow_mut() = Some(hook));
    }
}

#[cfg(all(unix, not(test)))]
fn run_before_rename(_path: &Path) {}

#[cfg(all(unix, test))]
fn note_migration_lock_wait() {
    if let Ok(path) = std::env::var("ELASTOS_LOCALHOST_MIGRATION_WAIT_PROBE") {
        let _ = std::fs::write(path, b"waiting");
    }
}

#[cfg(all(unix, test))]
fn kill_checkpoint(point: &str) {
    let Ok(want) = std::env::var("ELASTOS_LOCALHOST_MIGRATION_KILL_AT") else {
        return;
    };
    if want != point {
        return;
    }
    if let Ok(root) = std::env::var("ELASTOS_LOCALHOST_MIGRATION_CHILD_ROOT") {
        let _ = std::fs::write(Path::new(&root).join("kill-probe"), point);
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

#[cfg(unix)]
thread_local! {
    static MIGRATION_ROOT: std::cell::RefCell<std::path::PathBuf> =
        const { std::cell::RefCell::new(std::path::PathBuf::new()) };
    static PROGRESS_AT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
}

#[cfg(unix)]
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn set_migration_root(root: &Path) {
    MIGRATION_ROOT.with(|slot| *slot.borrow_mut() = root.to_path_buf());
    PROGRESS_AT.with(|slot| slot.set((0, unix_secs())));
}

#[cfg(unix)]
fn relative_path(path: &Path) -> String {
    MIGRATION_ROOT.with(|root| {
        path.strip_prefix(root.borrow().as_path())
            .unwrap_or(path)
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/")
    })
}

#[cfg(unix)]
fn localhost_refused(path: &Path, why: &str) -> anyhow::Error {
    let rel = relative_path(path);
    let cause = if why == "forged" {
        return anyhow::anyhow!("{rel} is not the migration record. {RECOVERY}");
    } else if why == "mismatch" {
        return anyhow::anyhow!(
            "{rel} does not match this Home (restored or copied folder, changed device key). Restore the matching identity/device.key, or move AppCapsules, ElastOS, Local, Users, and UsersAI aside to start empty, then restart."
        );
    } else if why.starts_with("larger") {
        why
    } else if why.contains("link") {
        "linked"
    } else if why.contains("changed") {
        "changed while read"
    } else if why.contains("decrypt") {
        "not decryptable"
    } else {
        "not readable"
    };
    anyhow::anyhow!("{rel} is {cause}. {RECOVERY}")
}

#[cfg(unix)]
fn localhost_write_refused(path: &Path, io_text: &str) -> anyhow::Error {
    let rel = relative_path(path);
    anyhow::anyhow!(
        "{rel} could not be written ({io_text}). Free space, or the folder's permissions, then restart."
    )
}

#[cfg(unix)]
fn note_progress() {
    PROGRESS_AT.with(|slot| {
        let (count, last) = slot.get();
        let count = count + 1;
        let now = unix_secs();
        if now.saturating_sub(last) >= 3 {
            let line = format!("localhost file migration checked {count} files");
            tracing::info!(target: "elastos", "{line}");
            #[cfg(test)]
            PROGRESS_LINES.with(|slot| slot.borrow_mut().push(line));
            slot.set((count, now));
        } else {
            slot.set((count, last));
        }
    });
}

#[cfg(unix)]
fn file_key_fingerprint(file_key: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(file_key);
    hasher.finalize().into()
}

#[cfg(unix)]
pub(crate) fn localhost_marker_record(file_key: &[u8; 32]) -> Vec<u8> {
    format!(
        "elastos-localhost-file-v1 1 {}\n",
        hex::encode(file_key_fingerprint(file_key))
    )
    .into_bytes()
}

#[cfg(unix)]
fn kept_mode(mode: u32) -> u32 {
    let perm = mode & 0o777;
    if perm & !0o600 == 0 {
        perm
    } else {
        0o600
    }
}

#[cfg(unix)]
pub(crate) fn localhost_file_key(device_key: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
    if *device_key == [0u8; 32] {
        anyhow::bail!(
            "identity/device.key is all zero. Restore a device key that is not all zero, then restart."
        );
    }
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, device_key);
    let mut okm = [0u8; 32];
    hk.expand(LOCALHOST_FILE_KEY_INFO, &mut okm)
        .map_err(|_| anyhow::anyhow!("localhost file key expansion failed"))?;
    Ok(okm)
}

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

#[cfg(unix)]
fn replace_file_fsync_rename(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    opened: Option<(&std::fs::File, u64)>,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

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
        .mode(mode)
        .open(&tmp)?;
    #[cfg(test)]
    kill_checkpoint("temp-created");
    file.set_permissions(std::fs::Permissions::from_mode(mode))?;
    if let Err(err) = (|| {
        charge_migration_write().map_err(io_error)?;
        #[cfg(test)]
        if let Some(err) = injected_write_error() {
            return Err(err);
        }
        file.write_all(bytes)?;
        charge_migration_write().map_err(io_error)?;
        file.sync_all()?;
        Ok(())
    })() {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    drop(file);
    run_before_rename(path);
    // The check and rename are not one operation. After this check returns
    // and before rename returns, a same-user swap can still replace the file.
    // This platform has no inode-conditional rename.
    if let Some((opened, read_len)) = opened {
        if let Err(err) = opened_file_still_matches(path, opened, read_len) {
            let _ = std::fs::remove_file(&tmp);
            return Err(refusal_io(err));
        }
    }
    charge_migration_write().map_err(io_error)?;
    if let Err(err) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    #[cfg(test)]
    kill_checkpoint("renamed");
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
fn refusal_io(err: anyhow::Error) -> std::io::Error {
    std::io::Error::other(format!("localhost-refusal\n{err}"))
}

#[cfg(unix)]
fn migration_io(path: &Path, why: &str, err: std::io::Error) -> anyhow::Error {
    let text = err.to_string();
    if text.contains("local apps stayed off") {
        return anyhow::anyhow!(text);
    }
    if let Some(sentence) = text.strip_prefix("localhost-refusal\n") {
        return anyhow::anyhow!("{sentence}");
    }
    if why == "cannot be replaced" {
        return localhost_write_refused(path, &text);
    }
    localhost_refused(path, why)
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

/// A header rules an envelope out only when it cannot be the start of one.
/// All whitespace, or `{`, can still be an envelope. Any other first byte cannot.
#[cfg(unix)]
fn header_rules_out_envelope(header: &[u8]) -> bool {
    let start = header
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(header.len());
    match header.get(start) {
        None | Some(b'{') => false,
        Some(_) => true,
    }
}

#[cfg(unix)]
fn migrate_localhost_envelope(
    path: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<()> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use zeroize::Zeroize;

    note_progress();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                localhost_refused(path, "is a link")
            } else {
                localhost_refused(path, "cannot be read")
            }
        })?;
    let meta = file
        .metadata()
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    if !meta.is_file() {
        return Err(localhost_refused(path, "is not a regular file"));
    }
    if meta.nlink() > 1 {
        return Err(localhost_refused(path, "is linked from another path"));
    }
    if meta.len() > LOCALHOST_ENVELOPE_LIMIT {
        let mut header = [0u8; ENVELOPE_HEADER];
        let read = file
            .read(&mut header)
            .with_context(|| localhost_refused(path, "cannot be read"))?;
        if header_rules_out_envelope(&header[..read]) {
            return Ok(());
        }
        return Err(localhost_refused(path, "larger than 32 MiB"));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(LOCALHOST_ENVELOPE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    if bytes.len() as u64 > LOCALHOST_ENVELOPE_LIMIT {
        return Err(localhost_refused(path, "larger than 32 MiB"));
    }
    run_before_replace(path);
    opened_file_still_matches(path, &file, bytes.len() as u64)?;
    if !localhost_provider::is_encrypted_envelope(&bytes) {
        return Ok(());
    }
    if let Ok(mut plaintext) = localhost_provider::decrypt_bytes(device_key, &bytes) {
        let sealed = localhost_provider::encrypt_bytes(file_key, &plaintext);
        plaintext.zeroize();
        let sealed = sealed.with_context(|| localhost_refused(path, "cannot be sealed"))?;
        opened_file_still_matches(path, &file, bytes.len() as u64)?;
        replace_file_fsync_rename(
            path,
            &sealed,
            kept_mode(meta.mode()),
            Some((&file, bytes.len() as u64)),
        )
        .map_err(|err| migration_io(path, "cannot be replaced", err))?;
        return Ok(());
    }
    if let Ok(mut plaintext) = localhost_provider::decrypt_bytes(file_key, &bytes) {
        plaintext.zeroize();
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

#[cfg(unix)]
enum MarkerPlan {
    Write,
    Keep,
}

#[cfg(unix)]
fn read_marker_plan(marker: &Path, file_key: &[u8; 32]) -> anyhow::Result<MarkerPlan> {
    let meta = match std::fs::symlink_metadata(marker) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(MarkerPlan::Write),
        Err(_) => return Err(localhost_refused(marker, "cannot be read")),
    };
    if meta.file_type().is_symlink() {
        return Err(localhost_refused(marker, "is a link"));
    }
    if !meta.is_file() {
        return Err(localhost_refused(marker, "is not a file"));
    }
    if meta.len() > 256 {
        return Err(localhost_refused(marker, "forged"));
    }
    let bytes = read_nofollow(marker).map_err(|_| localhost_refused(marker, "cannot be read"))?;
    if bytes == LOCALHOST_MIGRATION_RECORD {
        return Ok(MarkerPlan::Write);
    }
    let text = std::str::from_utf8(&bytes).unwrap_or("");
    let Some(rest) = text
        .strip_prefix("elastos-localhost-file-v1 ")
        .and_then(|rest| rest.strip_suffix('\n'))
    else {
        return Err(localhost_refused(marker, "forged"));
    };
    let Some(("1", hex_fingerprint)) = rest.split_once(' ') else {
        return Err(localhost_refused(marker, "forged"));
    };
    let Ok(found) = hex::decode(hex_fingerprint) else {
        return Err(localhost_refused(marker, "forged"));
    };
    if found.as_slice() == file_key_fingerprint(file_key) {
        Ok(MarkerPlan::Keep)
    } else {
        Err(localhost_refused(marker, "mismatch"))
    }
}

#[cfg(unix)]
fn identity_is_directory_or_absent(identity: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(identity) {
        Ok(meta) if meta.file_type().is_symlink() => Err(localhost_refused(identity, "is a link")),
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(localhost_refused(identity, "is not a directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(localhost_refused(identity, "cannot be read")),
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
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            tracing::info!(target: "elastos", "localhost file migration is waiting");
            #[cfg(test)]
            note_migration_lock_wait();
            file.lock()
                .with_context(|| localhost_refused(&lock_path, "cannot be locked"))?;
        }
        Err(err) => {
            return Err(err).with_context(|| localhost_refused(&lock_path, "cannot be locked"));
        }
    }
    Ok(LocalhostMigrationLock { _file: file })
}

#[cfg(unix)]
fn write_localhost_marker(marker: &Path, record: &[u8]) -> anyhow::Result<()> {
    let identity = marker.parent().ok_or_else(|| {
        anyhow::anyhow!("identity/localhost-file-key-v1 is not readable. {RECOVERY}")
    })?;
    ensure_identity_dir(identity)?;
    replace_file_fsync_rename(marker, record, 0o600, None)
        .map_err(|err| migration_io(marker, "cannot be replaced", err))?;
    Ok(())
}

#[cfg(unix)]
fn migrate_localhost_files_to_file_key(
    data_dir: &Path,
    device_key: &[u8; 32],
) -> anyhow::Result<()> {
    set_migration_root(data_dir);
    let identity = data_dir.join("identity");
    identity_is_directory_or_absent(&identity)?;
    let file_key = zeroize::Zeroizing::new(localhost_file_key(device_key)?);
    let marker = identity.join(LOCALHOST_MIGRATION_MARKER);
    read_marker_plan(&marker, &file_key)?;
    let _lock = acquire_migration_lock(data_dir)?;
    let plan = read_marker_plan(&marker, &file_key)?;
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
    if matches!(plan, MarkerPlan::Write) {
        write_localhost_marker(&marker, &localhost_marker_record(&file_key))?;
    }
    Ok(())
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

pub(crate) enum LocalhostBringup {
    Start(provider::BridgeProviderConfig),
    Refuse(String),
}

pub(crate) fn localhost_bringup(data_dir: &Path, device_key: &[u8; 32]) -> LocalhostBringup {
    match localhost_provider_bridge_config(data_dir, device_key) {
        Ok(config) => {
            elastos_server::local_apps::set_local_apps_refusal(data_dir, None);
            LocalhostBringup::Start(config)
        }
        Err(err) => {
            let sentence = err.to_string();
            elastos_server::local_apps::set_local_apps_refusal(data_dir, Some(sentence.clone()));
            LocalhostBringup::Refuse(sentence)
        }
    }
}
