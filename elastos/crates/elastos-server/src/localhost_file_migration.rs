//! The localhost file-key walker.
//!
//! A migration problem does not stop Home (`api/routes.rs` `health`,
//! `api/server.rs` `ServeDir`). The helper stays down, including `MyWebSite`
//! and `Public`, and every localhost route refuses with one sentence: the
//! relative path, the cause, and what to do. Nothing starts unfenced.
//!
//! `identity/localhost-file-key-v1` is format `1` plus
//! SHA-256(`elastos-localhost-file-key-fingerprint-v1\0` || file key). A
//! different fingerprint leaves files untouched while any of the five roots
//! is present (restored or copied folder, changed device key). Restoring the
//! matching identity/device.key makes that fingerprint match again, and the
//! files stay. Moving AppCapsules, ElastOS, Local, Users, and UsersAI aside,
//! so those roots are absent, makes the next start write a marker for this
//! device key and turn local apps on with an empty store. That decision runs
//! in `prepare_localhost_files` before startup creates the roots: gateway and
//! `home --browser` call it before the auth lock under `ElastOS`, and serve
//! calls it before `ensure_file_backed_roots`. When any of the five is already
//! present, that call does not walk. An empty root that
//! is still present is not moved aside. A matching marker still walks, so an
//! older build's later device-key file is rewritten. A file is an envelope only when
//! `is_encrypted_envelope` accepts it, in any field order. The walk reads a short
//! header first. If that header cannot start an envelope, the file is left alone
//! and its body is not read. A device-key envelope is rewritten onto the file key,
//! one file at a time, through the same temporary file, check, and rename, up to
//! `SEALED_READ_HARD_LIMIT`. That is the most `read_sealed_localhost_file` will
//! load: one `Vec` from `read_to_end`, then a second `Vec` from hex-decoding the
//! ciphertext. The rewrite holds about two copies of the file and drops the first
//! before it builds the new envelope. A longer file whose header can start an
//! envelope is left untouched and named; every other file still migrates. A later
//! start uses the size and time stored beside the marker and does not open a file
//! that still matches. The walk logs a count every few seconds. A waiter on
//! `identity/localhost-file-key.lock` logs that. The walk runs from
//! `setup_server_infrastructure`. `elastos serve` runs it and then spawns the
//! helper (`spawn_host_providers`). `elastos serve`
//! takes `host_lock.rs` `acquire_host_process_lock` before that
//! (`serve_cmd.rs` `run_serve`) and skips the lock when
//! `ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1`. `elastos gateway`, including
//! its public mode, and `elastos home --browser` also take that lock
//! (`gateway_cmd.rs`). A second one of these stops with "another ElastOS
//! host already owns". Gateway and `home --browser` call
//! `setup_gateway_infrastructure` or `setup_control_plane_infrastructure`
//! (`spawn_host_providers` is false). They run this same walk, so a bad file
//! turns local apps off there too, and they register the refusing provider so
//! System can show the sentence. They do not spawn the localhost helper.
//! Update and the provider host take the same lock and do not run this walk.
//! `elastos run`
//! of a data capsule calls `serve_web_capsule` (`main.rs`), which walks and
//! does not take the host lock. `elastos capsule` attaches to a running
//! runtime and does not walk. `elastos run` and a host can therefore overlap.
//! They cannot mix keys: on Unix the file key is HKDF-SHA256 of the device key
//! (info `elastos-localhost-file-v1`), and the migration lock lets one walk
//! write at a time. On Windows the helper still receives the device key, and
//! this slice does not rewrite files there.
//! `two_homes_on_one_data_folder_finish_on_one_key` runs two processes on one
//! folder and both finish on that same file key. A helper already running in
//! the other process is not stopped. A new inode keeps a mode that is a subset
//! of `0600`, else `0600`, and drops ACLs and extended attributes. Plaintext is
//! zeroized. The inode, the length, and the modification and change times,
//! including nanoseconds, are checked again after the temporary file is synced
//! and before `rename`. After that check returns and before `rename` returns, a
//! same-user swap can still replace the file. This platform has no
//! inode-conditional rename. A temporary marker file left by a crash is removed
//! at the start of every walk.

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
const LOCALHOST_TEMP_DIR: &str = "localhost-file-key-v1.tmpd";
#[cfg(unix)]
const LOCALHOST_SEEN: &str = "localhost-file-key-v1.seen";
#[cfg(unix)]
const ENVELOPE_HEADER: usize = 64;
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
    static CREATE_ERROR: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
    static BEFORE_REPLACE: std::cell::RefCell<Option<MigrationReplaceHook>> =
        std::cell::RefCell::new(None);
    static BEFORE_RENAME: std::cell::RefCell<Option<MigrationReplaceHook>> =
        std::cell::RefCell::new(None);
    static PROGRESS_CLOCK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static OPENS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
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

/// The next create of `identity/` or of the lock file reports this raw OS
/// code instead of creating the path. The test uses it for a full disk.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_create_error(code: Option<i32>) {
    CREATE_ERROR.with(|slot| slot.set(code));
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

/// Sets the progress clock. `None` uses the wall clock. A test moves this
/// forward inside the walk, so the progress row does not sleep.
#[cfg(all(unix, test))]
pub(crate) fn set_localhost_migration_progress_clock(now: Option<u64>) {
    PROGRESS_CLOCK.with(|slot| slot.set(now));
}

/// Bytes the walk read from file bodies since the last take. A header-only
/// decision stays within the header size.
#[cfg(all(unix, test))]
pub(crate) fn take_localhost_migration_bytes_read() -> u64 {
    BYTES_READ.with(|slot| slot.replace(0))
}

/// File-content opens since the last take. A stat of a settled file is not an open.
#[cfg(all(unix, test))]
pub(crate) fn take_localhost_migration_opens() -> u64 {
    OPENS.with(|slot| slot.replace(0))
}

#[cfg(all(unix, test))]
fn note_open() {
    OPENS.with(|slot| slot.set(slot.get() + 1));
}

#[cfg(all(unix, not(test)))]
fn note_open() {}

#[cfg(all(unix, test))]
fn note_bytes_read(n: usize) {
    BYTES_READ.with(|slot| slot.set(slot.get() + n as u64));
}

#[cfg(all(unix, not(test)))]
fn note_bytes_read(_n: usize) {}

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
fn injected_create_error() -> Option<std::io::Error> {
    CREATE_ERROR.with(|slot| slot.get().map(std::io::Error::from_raw_os_error))
}

#[cfg(all(unix, not(test)))]
fn injected_create_error() -> Option<std::io::Error> {
    None
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
fn progress_now() -> u64 {
    #[cfg(test)]
    if let Some(now) = PROGRESS_CLOCK.with(|slot| slot.get()) {
        return now;
    }
    unix_secs()
}

#[cfg(unix)]
fn set_migration_root(root: &Path) {
    MIGRATION_ROOT.with(|slot| *slot.borrow_mut() = root.to_path_buf());
    PROGRESS_AT.with(|slot| slot.set((0, progress_now())));
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
    if why == "forged" {
        return anyhow::anyhow!("{rel} is not the migration record. Delete {rel}, then restart.");
    }
    if why == "mismatch" {
        return anyhow::anyhow!(
            "{rel} does not match this Home (restored or copied folder, changed device key). Restore the matching identity/device.key, or move AppCapsules, ElastOS, Local, Users, and UsersAI aside to start empty, then restart."
        );
    }
    let (cause, remedy) = if why.starts_with("larger") {
        (why, "Move it out of the folder, then restart.")
    } else if why.contains("link") {
        (
            "linked",
            "Replace the link with a regular file, then restart.",
        )
    } else if why.contains("changed") {
        ("changed while read", "Leave it unchanged, then restart.")
    } else if why.contains("decrypt") {
        ("not decryptable", "Remove it, then restart.")
    } else if why.contains("not a regular") {
        (
            "not a regular file",
            "Replace it with a regular file, then restart.",
        )
    } else {
        ("not readable", "Make it readable, then restart.")
    };
    anyhow::anyhow!("{rel} is {cause}. {remedy}")
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
        let now = progress_now();
        if now.saturating_sub(last) >= 3 {
            let line = format!("localhost file migration checked {count} files");
            tracing::info!(target: "elastos", "{line}");
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
struct OpenedIdentity {
    dev: u64,
    ino: u64,
    nlink: u64,
    len: u64,
    mode: u32,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
fn opened_identity(meta: &std::fs::Metadata) -> OpenedIdentity {
    use std::os::unix::fs::MetadataExt;
    OpenedIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
        nlink: meta.nlink(),
        len: meta.len(),
        mode: meta.mode(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_nsec: meta.ctime_nsec(),
    }
}

/// Temps live in the walk's own directory, named by the relative path, so a
/// person's file is never removed because its name looks like a temp.
#[cfg(unix)]
fn migration_root() -> std::path::PathBuf {
    MIGRATION_ROOT.with(|slot| slot.borrow().clone())
}

#[cfg(unix)]
fn rewrite_temp_path(path: &Path) -> std::io::Result<std::path::PathBuf> {
    use sha2::Digest;
    use std::os::unix::fs::DirBuilderExt;

    let dir = migration_root().join("identity").join(LOCALHOST_TEMP_DIR);
    match std::fs::symlink_metadata(&dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        Err(err) => return Err(err),
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "localhost temp directory is not a directory",
            ));
        }
        Ok(_) => {}
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(relative_path(path).as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut name = std::ffi::OsString::from(".");
    name.push(hex::encode(digest));
    name.push(LOCALHOST_REWRITE_SUFFIX);
    Ok(dir.join(name))
}

#[cfg(unix)]
fn replace_file_fsync_rename(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    opened: Option<&OpenedIdentity>,
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "localhost file has no directory",
        )
    })?;
    let tmp = rewrite_temp_path(path)?;
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
    if let Some(opened) = opened {
        if let Err(err) = opened_file_still_matches(path, opened) {
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
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let mut bytes = Vec::new();
    file.by_ref().take(257).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(unix)]
#[derive(Clone, PartialEq, Eq)]
struct SeenFile {
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    hard: bool,
}

#[cfg(unix)]
enum MigratedFile {
    Settled,
    OverHard,
}

#[cfg(unix)]
fn seen_file(meta: &std::fs::Metadata, hard: bool) -> SeenFile {
    use std::os::unix::fs::MetadataExt;
    SeenFile {
        len: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        hard,
    }
}

#[cfg(unix)]
fn parse_seen(bytes: &[u8]) -> std::collections::HashMap<String, SeenFile> {
    let mut seen = std::collections::HashMap::new();
    let mut lines = std::str::from_utf8(bytes).unwrap_or("").lines();
    if lines.next() != Some("1") {
        return seen;
    }
    for line in lines {
        let mut parts = line.splitn(5, ' ');
        let (Some(len), Some(mtime), Some(mtime_nsec), Some(flag), Some(rel)) = (
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        if rel.is_empty() || (flag != "s" && flag != "h") {
            continue;
        }
        seen.insert(
            rel.to_string(),
            SeenFile {
                len,
                mtime,
                mtime_nsec,
                hard: flag == "h",
            },
        );
    }
    seen
}

#[cfg(unix)]
fn read_seen(path: &Path) -> anyhow::Result<std::collections::HashMap<String, SeenFile>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    let meta = match std::fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(std::collections::HashMap::new());
        }
        Err(_) => return Err(localhost_refused(path, "cannot be read")),
        Ok(meta) => meta,
    };
    if meta.file_type().is_symlink() {
        return Err(localhost_refused(path, "is a link"));
    }
    if !meta.is_file() {
        return Err(localhost_refused(path, "is not a file"));
    }
    if meta.len() > localhost_provider::ENVELOPE_BYTE_LIMIT {
        return Ok(std::collections::HashMap::new());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| localhost_refused(path, "cannot be read"))?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(meta.len())
        .read_to_end(&mut bytes)
        .map_err(|_| localhost_refused(path, "cannot be read"))?;
    Ok(parse_seen(&bytes))
}

#[cfg(unix)]
fn write_seen(
    path: &Path,
    seen: &std::collections::HashMap<String, SeenFile>,
) -> anyhow::Result<()> {
    let mut keys: Vec<&String> = seen.keys().collect();
    keys.sort();
    let mut text = String::from("1\n");
    for key in keys {
        let item = &seen[key];
        let flag = if item.hard { "h" } else { "s" };
        text.push_str(&format!(
            "{} {} {} {} {}\n",
            item.len, item.mtime, item.mtime_nsec, flag, key
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| localhost_refused(path, "cannot be read"))?;
    ensure_identity_dir(parent)?;
    replace_file_fsync_rename(path, text.as_bytes(), 0o600, None)
        .map_err(|err| migration_io(path, "cannot be replaced", err))?;
    Ok(())
}

#[cfg(unix)]
fn over_hard_sentence(names: &[String]) -> String {
    names
        .iter()
        .map(|name| {
            format!(
                "{name} is larger than this process can read. Move it out of the folder, then restart."
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(unix)]
fn opened_file_still_matches(path: &Path, opened: &OpenedIdentity) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let path_meta = std::fs::symlink_metadata(path)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    if path_meta.file_type().is_symlink() {
        return Err(localhost_refused(path, "is a link"));
    }
    let same = path_meta.is_file()
        && path_meta.nlink() == 1
        && opened.nlink == 1
        && path_meta.dev() == opened.dev
        && path_meta.ino() == opened.ino
        && path_meta.len() == opened.len
        && path_meta.mtime() == opened.mtime
        && path_meta.mtime_nsec() == opened.mtime_nsec
        && path_meta.ctime() == opened.ctime
        && path_meta.ctime_nsec() == opened.ctime_nsec;
    if !same {
        return Err(localhost_refused(path, "changed while it was being read"));
    }
    Ok(())
}

#[cfg(unix)]
fn migrate_localhost_envelope(
    path: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
) -> anyhow::Result<MigratedFile> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;

    note_progress();
    note_open();
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| {
            if err.raw_os_error() == Some(libc::ELOOP) {
                localhost_refused(path, "is a link")
            } else {
                localhost_refused(path, "cannot be read")
            }
        })?;
    let opened = opened_identity(
        &file
            .metadata()
            .with_context(|| localhost_refused(path, "cannot be read"))?,
    );
    if opened.nlink > 1 {
        return Err(localhost_refused(path, "is linked from another path"));
    }
    let mut header = [0u8; ENVELOPE_HEADER];
    let read = file
        .read(&mut header)
        .with_context(|| localhost_refused(path, "cannot be read"))?;
    note_bytes_read(read);
    if localhost_provider::header_rules_out_envelope(&header[..read])
        || localhost_provider::header_is_file_key_envelope(&header[..read])
    {
        return Ok(MigratedFile::Settled);
    }
    if opened.len > localhost_provider::SEALED_READ_HARD_LIMIT {
        return Ok(MigratedFile::OverHard);
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve(opened.len as usize).is_err() {
        return Ok(MigratedFile::OverHard);
    }
    bytes.extend_from_slice(&header[..read]);
    if opened.len > read as u64 {
        file.by_ref()
            .take(opened.len - read as u64)
            .read_to_end(&mut bytes)
            .with_context(|| localhost_refused(path, "cannot be read"))?;
        note_bytes_read(bytes.len().saturating_sub(read));
    }
    if bytes.len() as u64 > localhost_provider::SEALED_READ_HARD_LIMIT {
        return Ok(MigratedFile::OverHard);
    }
    run_before_replace(path);
    opened_file_still_matches(path, &opened)?;
    match localhost_provider::rekey_device_envelope(device_key, file_key, bytes) {
        Ok(localhost_provider::RekeyOutcome::NotEnvelope)
        | Ok(localhost_provider::RekeyOutcome::AlreadyFileKey) => Ok(MigratedFile::Settled),
        Ok(localhost_provider::RekeyOutcome::Rewritten(sealed)) => {
            opened_file_still_matches(path, &opened)?;
            replace_file_fsync_rename(path, &sealed, kept_mode(opened.mode), Some(&opened))
                .map_err(|err| migration_io(path, "cannot be replaced", err))?;
            Ok(MigratedFile::Settled)
        }
        Err(err) if err.to_string().contains("does not decrypt") => {
            Err(localhost_refused(path, "does not decrypt"))
        }
        Err(err) => Err(err).with_context(|| localhost_refused(path, "cannot be sealed")),
    }
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
    seen: &std::collections::HashMap<String, SeenFile>,
    next: &mut std::collections::HashMap<String, SeenFile>,
    over_hard: &mut Vec<String>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let names = directory_names(dir)?;
    for name in &names {
        let path = dir.join(name);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| localhost_refused(&path, "cannot be read"))?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            return Err(localhost_refused(&path, "is a link"));
        }
        if file_type.is_dir() {
            migrate_localhost_tree(&path, device_key, file_key, seen, next, over_hard)?;
            continue;
        }
        if !file_type.is_file() {
            return Err(localhost_refused(&path, "is not a regular file"));
        }
        if meta.nlink() > 1 {
            return Err(localhost_refused(&path, "is linked from another path"));
        }
        let rel = relative_path(&path);
        if let Some(old) = seen.get(&rel) {
            if old.len == meta.len()
                && old.mtime == meta.mtime()
                && old.mtime_nsec == meta.mtime_nsec()
            {
                if old.hard {
                    over_hard.push(rel.clone());
                }
                next.insert(rel, old.clone());
                continue;
            }
        }
        let remembered = seen_file(&meta, false);
        match migrate_localhost_envelope(&path, device_key, file_key)? {
            MigratedFile::Settled => {
                let after = std::fs::symlink_metadata(&path)
                    .with_context(|| localhost_refused(&path, "cannot be read"))?;
                next.insert(rel, seen_file(&after, false));
            }
            MigratedFile::OverHard => {
                over_hard.push(rel.clone());
                next.insert(
                    rel,
                    SeenFile {
                        hard: true,
                        ..remembered
                    },
                );
            }
        }
    }
    let again = directory_names(dir)?;
    if names != again {
        return Err(localhost_refused(dir, "changed while it was being read"));
    }
    Ok(())
}

#[cfg(unix)]
enum MarkerPlan {
    Write,
    Keep,
    Mismatch,
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
    if found.len() != 32 {
        return Err(localhost_refused(marker, "forged"));
    }
    if found.as_slice() == file_key_fingerprint(file_key) {
        Ok(MarkerPlan::Keep)
    } else {
        Ok(MarkerPlan::Mismatch)
    }
}

#[cfg(unix)]
fn encrypted_roots_absent(data_dir: &Path) -> anyhow::Result<bool> {
    for root in LOCALHOST_ENCRYPTED_ROOTS {
        let path = data_dir.join(root);
        match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| localhost_refused(&path, "cannot be read"));
            }
            Ok(_) => return Ok(false),
        }
    }
    Ok(true)
}

/// A mismatched marker with any root still present refuses before a write.
/// When all five roots are absent, the marker is rewritten for this Home.
#[cfg(unix)]
fn plan_for_this_home(
    data_dir: &Path,
    marker: &Path,
    file_key: &[u8; 32],
) -> anyhow::Result<MarkerPlan> {
    match read_marker_plan(marker, file_key)? {
        MarkerPlan::Mismatch => {
            if encrypted_roots_absent(data_dir)? {
                Ok(MarkerPlan::Write)
            } else {
                Err(localhost_refused(marker, "mismatch"))
            }
        }
        plan => Ok(plan),
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
            if let Some(err) = injected_create_error() {
                return Err(localhost_write_refused(identity, &err.to_string()));
            }
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
                Err(err) => Err(localhost_write_refused(identity, &err.to_string())),
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
    if let Some(err) = injected_create_error() {
        return Err(localhost_write_refused(&lock_path, &err.to_string()));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|err| localhost_write_refused(&lock_path, &err.to_string()))?;
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
fn sweep_owned_temp_dir(data_dir: &Path) -> anyhow::Result<()> {
    let dir = data_dir.join("identity").join(LOCALHOST_TEMP_DIR);
    let meta = match std::fs::symlink_metadata(&dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| localhost_refused(&dir, "cannot be read")),
        Ok(meta) => meta,
    };
    if meta.file_type().is_symlink() {
        return Err(localhost_refused(&dir, "is a link"));
    }
    if !meta.is_dir() {
        return Err(localhost_refused(&dir, "is not a directory"));
    }
    for entry in
        std::fs::read_dir(&dir).with_context(|| localhost_refused(&dir, "cannot be read"))?
    {
        let entry = entry.with_context(|| localhost_refused(&dir, "cannot be read"))?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| localhost_refused(&path, "cannot be read"))?;
        if meta.file_type().is_symlink() {
            return Err(localhost_refused(&path, "is a link"));
        }
        if !meta.is_file() || std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
            return Err(localhost_refused(&path, "is not a regular file"));
        }
        charge_migration_write()?;
        std::fs::remove_file(&path)
            .map_err(|err| localhost_write_refused(&path, &err.to_string()))?;
    }
    Ok(())
}

#[cfg(unix)]
fn write_localhost_marker(marker: &Path, record: &[u8]) -> anyhow::Result<()> {
    let identity = marker.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "identity/localhost-file-key-v1 is not readable. Make it readable, then restart."
        )
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
    plan_for_this_home(data_dir, &marker, &file_key)?;
    let _lock = acquire_migration_lock(data_dir)?;
    let plan = plan_for_this_home(data_dir, &marker, &file_key)?;
    sweep_owned_temp_dir(data_dir)?;
    let seen_path = identity.join(LOCALHOST_SEEN);
    let seen = if matches!(plan, MarkerPlan::Keep) {
        read_seen(&seen_path)?
    } else {
        std::collections::HashMap::new()
    };
    let mut next = std::collections::HashMap::new();
    let mut over_hard = Vec::new();
    for root in LOCALHOST_ENCRYPTED_ROOTS {
        let path = data_dir.join(root);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(localhost_refused(&path, "is a link"));
            }
            Ok(meta) if meta.is_dir() => {
                migrate_localhost_tree(
                    &path,
                    device_key,
                    &file_key,
                    &seen,
                    &mut next,
                    &mut over_hard,
                )?;
            }
            Ok(_) => return Err(localhost_refused(&path, "is not a directory")),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| localhost_refused(&path, "cannot be read"));
            }
        }
    }
    if next != seen || !seen_path.is_file() {
        write_seen(&seen_path, &next)?;
    }
    if matches!(plan, MarkerPlan::Write) {
        write_localhost_marker(&marker, &localhost_marker_record(&file_key))?;
    }
    if over_hard.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(over_hard_sentence(&over_hard)))
    }
}

/// Localhost-provider init config.
///
/// On Unix, files under the five encrypted roots are rewritten onto the HKDF
/// file key before this returns. The encryption field is that file key.
/// On Windows, files are not rewritten and the field is the device key.
/// The "never the device key" claim is the Unix field only.
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

/// Decide a mismatched marker before startup creates the five roots.
///
/// When any of AppCapsules, ElastOS, Local, Users, or UsersAI is already
/// present, this returns without a walk. The later bringup walks once.
/// When all five are absent, this rewrites the marker for this device key
/// before gateway creates `ElastOS/System/Auth` or serve creates the roots.
/// An empty root the person left in place is still present.
pub(crate) fn prepare_localhost_files(data_dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        if !encrypted_roots_absent(data_dir)? {
            return Ok(());
        }
        let device_key = elastos_identity::load_or_create_device_key(data_dir)?;
        let _ = localhost_bringup(data_dir, &device_key);
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
    }
    Ok(())
}
