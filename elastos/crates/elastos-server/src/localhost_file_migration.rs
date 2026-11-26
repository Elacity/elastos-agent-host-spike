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
//! older build's later device-key file is rewritten, one way: an older release cannot open it. A refused start does not rewrite an older-format file. A new-format header and a plain file are settled unread. A later
//! start uses the size and time stored beside the marker and does not open a file
//! that still matches. The walk logs a count every few seconds. A waiter on
//! `identity/localhost-file-key.lock` logs that. The walk runs from
//! `setup_server_infrastructure`. `elastos serve` runs it and then spawns the
//! helper (`spawn_host_providers`). `elastos serve`
//! takes `host_lock.rs` `start_host_for_agents` before that
//! (`serve_cmd.rs` `run_serve`) and skips the lock when
//! `ELASTOS_ALLOW_SUBORDINATE_RUNTIME_HOST=1`. `elastos gateway`, including
//! its public mode, and `elastos home --browser` take that same lock and call
//! `prepare_localhost_files` only after the lock is held, before auth creates
//! `ElastOS` (`gateway_cmd.rs`). A second one of these stops with "another ElastOS
//! host already owns". Gateway and `home --browser` call
//! `setup_gateway_infrastructure` or `setup_control_plane_infrastructure`
//! (`spawn_host_providers` is false). They run this same walk. A foreign or undecryptable old-format file turns local apps off; an unparsable one is left in place and refuses on open. They register the refusing provider so
//! System can show the sentence. They do not spawn the localhost helper.
//! Update and the provider host take the same lock and do not run this walk.
//! `elastos run` of a data capsule and `elastos open` call `serve_web_capsule`
//! (`main.rs`), which walks and does not take the host lock. `elastos capsule`
//! attaches to a running runtime and does not walk. `elastos run`, `elastos open`,
//! and a host can therefore overlap.
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
//! inode-conditional rename. At the start of a walk, identity/ loses the
//! marker and seen temporary files when each is a regular file this Home
//! owns. A symlink stays, with its target, and any other name stays.

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
#[rustfmt::skip]
thread_local! {
    static MIGRATION_ROOT: std::cell::RefCell<std::path::PathBuf> =
        const { std::cell::RefCell::new(std::path::PathBuf::new()) };
    static PROGRESS_AT: std::cell::Cell<(u64, u64)> = const { std::cell::Cell::new((0, 0)) };
    static CANON_ROOT: std::cell::RefCell<std::path::PathBuf> = const { std::cell::RefCell::new(std::path::PathBuf::new()) };
    static HELD: std::cell::RefCell<Vec<(std::path::PathBuf, Vec<u8>, OpenedIdentity)>> = const { std::cell::RefCell::new(Vec::new()) };
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
#[rustfmt::skip]
fn relative_path(path: &Path) -> String {
    MIGRATION_ROOT.with(|root| {
        let root = root.borrow();
        let shown = if path == root.as_path() { root.file_name().unwrap_or(path.as_os_str()) } else { path.strip_prefix(root.as_path()).unwrap_or(path).as_os_str() };
        std::path::Path::new(shown).components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect::<Vec<_>>().join("/")
    })
}

#[cfg(unix)]
#[rustfmt::skip]
fn localhost_refused(path: &Path, why: &str) -> anyhow::Error {
    let rel = relative_path(path);
    if why == "forged" {
        return anyhow::anyhow!("{rel} is not the migration record. Delete {rel}, then restart.");
    }
    if why == "cannot be sealed" {
        return anyhow::anyhow!("{rel} cannot be sealed. Remove it, then restart.");
    }
    if why == "mismatch" {
        return anyhow::anyhow!(
            "{rel} does not match this Home (restored or copied folder, changed device key). Restore the matching identity/device.key, or move AppCapsules, ElastOS, Local, Users, and UsersAI aside to start empty, then restart."
        );
    }
    let (cause, remedy) = if why.starts_with("larger") {
        (why, "Move it out of the folder, then restart.")
    } else if why.contains("directory link") {
        (
            "a directory link",
            "Replace the link with a directory, then restart.",
        )
    } else if why.contains("changed") {
        ("changed while read", "Leave it unchanged, then restart.")
    } else if why.contains("marker link") {
        ("linked", "Remove the link, then restart.")
    } else if why.contains("decrypt") {
        return anyhow::anyhow!(
            "{rel} does not decrypt. Restore identity/device.key, or move the file aside, then restart."
        );
    } else if why.contains("socket") {
        ("a socket", "Remove the socket, then restart.")
    } else if why.contains("not a directory") {
        (
            "not a directory",
            "Replace it with a directory, then restart.",
        )
    } else if why.contains("pipe") {
        ("a pipe", "Remove the pipe, then restart.")
    } else if why.contains("locked") {
        ("locked", "Stop the other Home, then restart.")
    } else if why.contains("not a file") {
        ("not a file", "Remove the directory, then restart.")
    } else if why.contains("not a regular") {
        (
            "not a regular file",
            "Replace it with a regular file, then restart.",
        )
    } else if why.contains("another path") { ("linked from another path", "Remove the other names for this file, or copy it to a new name and delete it, then restart.")
    } else if why.contains("link") {
        (
            "linked",
            "Replace the link with a regular file, then restart.",
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
        "{rel} could not be written ({io_text}). Free space, or fix the folder's permissions, then restart."
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

#[cfg(unix)]
fn is_owned_rewrite_temp(name: &std::ffi::OsStr) -> bool {
    let Some(hex_name) = name
        .to_str()
        .and_then(|name| name.strip_prefix('.'))
        .and_then(|rest| rest.strip_suffix(LOCALHOST_REWRITE_SUFFIX))
    else {
        return false;
    };
    hex_name.len() == 64 && hex_name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(unix)]
pub(crate) fn rewrite_temp_path(path: &Path) -> std::io::Result<std::path::PathBuf> {
    use sha2::Digest;

    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("localhost file has no directory"))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(relative_path(path).as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut name = std::ffi::OsString::from(".");
    name.push(hex::encode(digest));
    name.push(LOCALHOST_REWRITE_SUFFIX);
    Ok(parent.join(name))
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
    stamp: (u64, u64, i64, i64),
    hard: bool,
}

#[cfg(unix)]
enum MigratedFile {
    Settled,
    OverHard,
    Held,
}

#[cfg(unix)]
fn seen_file(meta: &std::fs::Metadata, hard: bool) -> SeenFile {
    use std::os::unix::fs::MetadataExt;
    SeenFile {
        len: meta.len(),
        mtime: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        stamp: (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
        hard,
    }
}

#[cfg(unix)]
#[rustfmt::skip]
fn parse_seen(bytes: &[u8]) -> std::collections::HashMap<String, SeenFile> {
    let mut seen = std::collections::HashMap::new();
    let mut lines = std::str::from_utf8(bytes).unwrap_or("").lines();
    if lines.next() != Some("3") {
        return seen;
    }
    for line in lines {
        let mut parts = line.splitn(9, ' ');
        let (Some(len), Some(mtime), Some(mtime_nsec), Some(dev), Some(ino), Some(ctime), Some(ctime_nsec), Some(flag), Some(hex_rel)) = (
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next().and_then(|text| text.parse().ok()),
            parts.next(),
            parts.next(),
        ) else {
            return std::collections::HashMap::new();
        };
        let Some(rel) = hex::decode(hex_rel)
            .ok()
            .and_then(|raw| String::from_utf8(raw).ok())
        else {
            return std::collections::HashMap::new();
        };
        if rel.is_empty() || (flag != "s" && flag != "h") {
            return std::collections::HashMap::new();
        }
        seen.insert(
            rel,
            SeenFile {
                len,
                mtime,
                mtime_nsec,
                stamp: (dev, ino, ctime, ctime_nsec),
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
    refuse_special(path, &meta, "is a link")?;
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
#[rustfmt::skip]
fn write_seen(
    path: &Path,
    seen: &std::collections::HashMap<String, SeenFile>,
) -> anyhow::Result<()> {
    let mut keys: Vec<&String> = seen.keys().collect();
    keys.sort();
    let mut text = String::from("3\n");
    for key in keys {
        let item = &seen[key];
        let flag = if item.hard { "h" } else { "s" };
        let coded = hex::encode(key.as_bytes());
        let line = format!("{} {} {} {} {} {} {} {} {}\n", item.len, item.mtime, item.mtime_nsec, item.stamp.0, item.stamp.1, item.stamp.2, item.stamp.3, flag, coded);
        if text.len() + line.len() > localhost_provider::ENVELOPE_BYTE_LIMIT as usize { break; }
        text.push_str(&line);
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
fn short_middle(name: &str, max: usize) -> String {
    if name.len() <= max {
        return name.to_string();
    }
    let max = max.max(5);
    let tail = (max - 3) / 2;
    let head = (0..=max - 3 - tail)
        .rev()
        .find(|&n| name.is_char_boundary(n))
        .unwrap_or(0);
    let from = name.len() - tail;
    let tail_at = (from..=name.len())
        .find(|&n| name.is_char_boundary(n))
        .unwrap_or(name.len());
    format!("{}...{}", &name[..head], &name[tail_at..])
}

#[cfg(unix)]
fn over_hard_sentence(names: &[String]) -> String {
    let mut text = String::new();
    let more = " more files are larger than this process can read. Move them out of the folder, then restart.";
    let hold_for = |after: usize| {
        let rest = names.len().saturating_sub(after);
        if rest == 0 {
            0
        } else {
            format!(" {rest}{more}").len()
        }
    };
    let mut put = |line: String, hold: usize| -> bool {
        let extra = usize::from(!text.is_empty());
        if text.len() + extra + line.len() + hold > 512 {
            return false;
        }
        if extra == 1 {
            text.push(' ');
        }
        text.push_str(&line);
        true
    };
    let mut named = 0;
    for name in names.iter().take(4) {
        let line = format!(
            "{name} is larger than this process can read. Move it out of the folder, then restart."
        );
        let hold = hold_for(named + 1);
        if !put(line, hold) {
            if named == 0 {
                let fixed = " is larger than this process can read. Move it out of the folder, then restart.";
                let short = short_middle(name, 512usize.saturating_sub(fixed.len() + hold));
                if put(format!("{short}{fixed}"), hold) {
                    named = 1;
                }
            }
            break;
        }
        named += 1;
    }
    let rest = names.len().saturating_sub(named);
    if rest > 0 {
        let more = format!(
            "{rest} more files are larger than this process can read. Move them out of the folder, then restart."
        );
        let _ = put(more, 0);
    }
    text
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
#[rustfmt::skip]
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
    let (plain, extra) = localhost_provider::reads_as_plain_bytes(&header[..read], opened.len, &mut file).with_context(|| localhost_refused(path, "cannot be read"))?;
    note_bytes_read(extra as usize);
    // A file-key header is not plain, and its body stays unread at start.
    if plain || localhost_provider::header_is_file_key_envelope(&header[..read]) {
        return Ok(MigratedFile::Settled);
    }
    if extra > 0 { std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(read as u64)).map_err(|_| localhost_refused(path, "cannot be read"))?; }
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
            HELD.with(|slot| slot.borrow_mut().push((path.to_path_buf(), sealed, opened)));
            Ok(MigratedFile::Held)
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
fn sweep_rewrite_temps(dir: &Path) -> anyhow::Result<()> {
    for name in directory_names(dir)? {
        if !is_owned_rewrite_temp(&name) {
            continue;
        }
        let path = dir.join(name);
        std::fs::remove_file(&path)
            .map_err(|err| localhost_write_refused(&path, &err.to_string()))?;
    }
    Ok(())
}

#[cfg(unix)]
#[rustfmt::skip]
fn migrate_localhost_tree(
    dir: &Path,
    device_key: &[u8; 32],
    file_key: &[u8; 32],
    seen: &std::collections::HashMap<String, SeenFile>,
    next: &mut std::collections::HashMap<String, SeenFile>,
    over_hard: &mut Vec<String>,
) -> anyhow::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    sweep_rewrite_temps(dir)?;
    let names = directory_names(dir)?;
    for name in &names {
        let path = dir.join(name);
        let meta = std::fs::symlink_metadata(&path)
            .with_context(|| localhost_refused(&path, "cannot be read"))?;
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            let why = if std::fs::metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                "is a directory link"
            } else {
                "is a link"
            };
            let inside = std::fs::canonicalize(&path).ok().is_some_and(|t| CANON_ROOT.with(|s| t.starts_with(s.borrow().as_path())));
            if !inside { return Err(localhost_refused(&path, why)); }
            continue;
        }
        if file_type.is_fifo() || file_type.is_socket() {
            let why = ["is a pipe", "is a socket"][usize::from(file_type.is_socket())];
            return Err(localhost_refused(&path, why));
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
                && old.stamp == (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())
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
            MigratedFile::Held => {}
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
    refuse_special(marker, &meta, "is a marker link")?;
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
#[rustfmt::skip]
fn encrypted_roots_absent(data_dir: &Path) -> anyhow::Result<bool> {
    for root in LOCALHOST_ENCRYPTED_ROOTS {
        let path = data_dir.join(root);
        match std::fs::symlink_metadata(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                let named = path.parent().filter(|p| *p == data_dir).unwrap_or(&path);
                return Err(err).with_context(|| localhost_refused(named, "cannot be read"));
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
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(localhost_refused(identity, "is a directory link"))
        }
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
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(localhost_refused(identity, "is a directory link"))
        }
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
                            Err(localhost_refused(identity, "is a directory link"))
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
        refuse_special(&lock_path, &meta, "is a link")?;
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
fn sweep_identity_temps(identity: &Path) -> anyhow::Result<()> {
    let home = std::fs::symlink_metadata(identity)
        .map_err(|_| localhost_refused(identity, "cannot be read"))?;
    if home.file_type().is_symlink() || !home.is_dir() {
        return Ok(());
    }
    let owner = std::os::unix::fs::MetadataExt::uid(&home);
    for name in [LOCALHOST_MIGRATION_MARKER, LOCALHOST_SEEN] {
        let path = rewrite_temp_path(&identity.join(name))?;
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_file() && std::os::unix::fs::MetadataExt::uid(&meta) == owner {
            std::fs::remove_file(&path)
                .map_err(|err| localhost_write_refused(&path, &err.to_string()))?;
        }
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
#[rustfmt::skip]
fn commit_held(next: &mut std::collections::HashMap<String, SeenFile>) -> anyhow::Result<()> {
    for (p, b, o) in HELD.with(|s| std::mem::take(&mut *s.borrow_mut())) {
        replace_file_fsync_rename(&p, &b, kept_mode(o.mode), Some(&o)).map_err(|e| migration_io(&p, "cannot be replaced", e))?;
        next.insert(relative_path(&p), seen_file(&std::fs::symlink_metadata(&p).with_context(|| localhost_refused(&p, "cannot be read"))?, false));
    }
    Ok(())
}
#[cfg(unix)]
struct ClearHeld;
#[cfg(unix)]
#[rustfmt::skip]
impl Drop for ClearHeld { fn drop(&mut self) { HELD.with(|s| s.borrow_mut().clear()); } }

#[cfg(unix)]
#[rustfmt::skip]
fn migrate_localhost_files_to_file_key(
    data_dir: &Path,
    device_key: &[u8; 32],
) -> anyhow::Result<()> {
    set_migration_root(data_dir);
    let _clear_held = ClearHeld;
    let identity = data_dir.join("identity");
    identity_is_directory_or_absent(&identity)?;
    let file_key = zeroize::Zeroizing::new(localhost_file_key(device_key)?);
    let marker = identity.join(LOCALHOST_MIGRATION_MARKER);
    plan_for_this_home(data_dir, &marker, &file_key)?;
    let _lock = acquire_migration_lock(data_dir)?;
    let plan = plan_for_this_home(data_dir, &marker, &file_key)?;
    sweep_identity_temps(&identity)?;
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
                return Err(localhost_refused(&path, "is a directory link"));
            }
            Ok(meta) if meta.is_dir() => {
                let canon = std::fs::canonicalize(&path).map_err(|_| localhost_refused(&path, "cannot be read"))?;
                CANON_ROOT.with(|slot| *slot.borrow_mut() = canon);
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
    if !over_hard.is_empty() { return Err(anyhow::anyhow!(over_hard_sentence(&over_hard))); }
    commit_held(&mut next)?;
    if next != seen || !seen_path.is_file() {
        write_seen(&seen_path, &next)?;
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
/// On Windows, files are not rewritten, the field is the device key, and `extra.file_key` is false.
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
    let (device_key_hex, given_file_key) = {
        use zeroize::Zeroize;
        migrate_localhost_files_to_file_key(data_dir, device_key)?;
        let mut file_key = localhost_file_key(device_key)?;
        let file_key_hex = hex::encode(file_key);
        file_key.zeroize();
        (file_key_hex, true)
    };
    #[cfg(not(unix))]
    let (device_key_hex, given_file_key) = (hex::encode(device_key), false);
    Ok(provider::BridgeProviderConfig {
        base_path: data_dir.to_string_lossy().to_string(),
        allowed_paths: file_backed_prefixes(),
        read_only: false,
        encryption_key: device_key_hex,
        extra: serde_json::json!({ "file_key": given_file_key }),
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
            let fresh = err.to_string();
            if elastos_server::local_apps::local_apps_refusal(data_dir).is_none() {
                elastos_server::local_apps::set_local_apps_refusal(data_dir, Some(fresh.clone()));
            }
            LocalhostBringup::Refuse(
                elastos_server::local_apps::local_apps_refusal(data_dir).unwrap_or(fresh),
            )
        }
    }
}

/// Decide a mismatched marker before startup creates the five roots.
///
/// When any of AppCapsules, ElastOS, Local, Users, or UsersAI is already
/// present, this returns without a walk. The later bringup walks once.
/// When all five are absent, this rewrites the marker for this device key
/// before gateway creates `ElastOS/System/Auth` or serve creates the roots.
/// An empty root the person left in place is still present. A refusal is
/// kept and this returns Ok, so Home starts and the roots stay absent.
#[rustfmt::skip]
pub(crate) fn prepare_localhost_files(data_dir: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        set_migration_root(data_dir);
        if let Err(err) = (|| -> anyhow::Result<()> {
        if !encrypted_roots_absent(data_dir)? {
            return Ok(());
        }
        let device_key = elastos_identity::load_or_create_device_key(data_dir)?;
        if let LocalhostBringup::Refuse(sentence) = localhost_bringup(data_dir, &device_key) {
            return Err(anyhow::anyhow!(sentence));
        }
        Ok(())
        })() {
            if elastos_server::local_apps::local_apps_refusal(data_dir).is_none() {
                elastos_server::local_apps::set_local_apps_refusal(data_dir, Some(err.to_string()));
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = data_dir;
    }
    Ok(())
}

#[cfg(unix)]
fn refuse_special(path: &Path, meta: &std::fs::Metadata, link: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    let kind = meta.file_type();
    let why = if kind.is_symlink() {
        link
    } else if kind.is_fifo() || kind.is_socket() {
        ["is a pipe", "is a socket"][usize::from(kind.is_socket())]
    } else if kind.is_dir() {
        "is not a file"
    } else if kind.is_file() {
        return Ok(());
    } else {
        "is not a regular file"
    };
    Err(localhost_refused(path, why))
}

#[cfg(all(test, not(unix)))]
mod windows_header {
    use super::localhost_provider_bridge_config;

    #[test]
    fn a_home_without_a_file_key_asks_for_the_old_header() {
        let dir = tempfile::tempdir().unwrap();
        let device_key = [0x5au8; 32];
        let config = localhost_provider_bridge_config(dir.path(), &device_key).unwrap();
        assert_eq!(config.encryption_key, hex::encode(device_key));
        assert_eq!(config.extra["file_key"], serde_json::json!(false));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{parse_seen, write_seen, SeenFile};

    #[test]
    fn a_seen_file_stays_within_the_envelope_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("localhost-file-key-v1.seen");
        let mut seen = std::collections::HashMap::new();
        let kept = SeenFile {
            len: 1,
            mtime: 2,
            mtime_nsec: 3,
            stamp: (4, 5, 6, 7),
            hard: false,
        };
        seen.insert("Users/a.bin".to_string(), kept.clone());
        seen.insert("z".repeat(20_000_000), kept);
        write_seen(&path, &seen).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() as u64 <= localhost_provider::ENVELOPE_BYTE_LIMIT);
        let parsed = parse_seen(&bytes);
        assert!(parsed.contains_key("Users/a.bin"));
        assert_eq!(parsed.len(), 1);
    }
}
