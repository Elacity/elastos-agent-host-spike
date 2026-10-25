use super::*;
use rustix::fs::{self as at, AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const MAX_WALLET_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_WALLET_STORAGE_KEY_BYTES: usize = 128;
pub(super) const BASE_PATH_MISSING_REASON: &str = "wallet-provider requires base_path";
pub(super) const BASE_PATH_EMPTY_REASON: &str = "wallet-provider base_path must not be empty";
pub(super) const BASE_PATH_RELATIVE_REASON: &str =
    "wallet-provider base_path must be an absolute path";

// Key installation publishes the key with a hard link and then removes the
// staging link. The process-local lock keeps that staging link invisible to
// sibling bootstrap calls so the exclusive-link check never refuses it. A
// second process that observes the staging window fails closed instead.
static KEY_BOOTSTRAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    static ACCESSED_PATHS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn reset_accessed_paths() {
    ACCESSED_PATHS.with(|paths| paths.borrow_mut().clear());
}

#[cfg(test)]
pub(super) fn take_accessed_paths() -> Vec<PathBuf> {
    ACCESSED_PATHS.with(|paths| std::mem::take(&mut *paths.borrow_mut()))
}

#[cfg(test)]
fn record_access(path: &Path) {
    ACCESSED_PATHS.with(|paths| paths.borrow_mut().push(path.to_path_buf()));
}

#[cfg(not(test))]
#[inline]
fn record_access(_path: &Path) {}

/// Validate the Runtime-supplied base directory and return it as a path.
pub(super) fn resolve_base_path(base_path: Option<&serde_json::Value>) -> Result<PathBuf, String> {
    let Some(value) = base_path else {
        return Err(BASE_PATH_MISSING_REASON.to_string());
    };
    let Some(value) = value.as_str() else {
        return Err("wallet-provider base_path must be a string".to_string());
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(BASE_PATH_EMPTY_REASON.to_string());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(BASE_PATH_RELATIVE_REASON.to_string());
    }
    Ok(path.to_path_buf())
}

/// The wallet directory is the only writable root the provider owns.
pub(super) fn wallet_dir_for_base(base_path: &Path) -> PathBuf {
    base_path
        .join("ElastOS")
        .join("SystemServices")
        .join("Wallet")
}

pub(super) fn store_path_for_wallet_dir(wallet_dir: &Path) -> PathBuf {
    wallet_dir.join("wallet-state.json")
}

/// An open directory owns all wallet effects for the lifetime of an Init.
/// Renaming or replacing any ancestor cannot redirect its descriptor-relative IO.
pub(super) struct WalletStorage {
    path: PathBuf,
    directory: File,
}

impl WalletStorage {
    /// This is the single path admission point for store and key operations.
    fn bind<'a>(&'a self, path: &'a Path, label: &str) -> Result<Leaf<'a>, String> {
        if !path.is_absolute() {
            return Err(format!(
                "{label} must be an absolute path inside the configured wallet directory"
            ));
        }
        let relative = path.strip_prefix(&self.path).ok();
        let name = relative
            .and_then(|relative| {
                let mut components = relative.components();
                match (components.next(), components.next()) {
                    (Some(Component::Normal(name)), None) => Some(name),
                    _ => None,
                }
            })
            .ok_or_else(|| {
                format!(
                    "{label} must stay inside the configured wallet directory: {}",
                    path.display()
                )
            })?;
        Ok(Leaf {
            root: self,
            name,
            path,
        })
    }
}

struct Leaf<'a> {
    root: &'a WalletStorage,
    name: &'a OsStr,
    path: &'a Path,
}

impl Leaf<'_> {
    fn stat(&self) -> Result<Stat, Errno> {
        record_access(self.path);
        at::statat(&self.root.directory, self.name, AtFlags::SYMLINK_NOFOLLOW)
    }

    fn open(&self, flags: OFlags) -> Result<File, Errno> {
        record_access(self.path);
        at::openat(
            &self.root.directory,
            self.name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::RUSR | Mode::WUSR,
        )
        .map(File::from)
    }

    fn remove(&self) -> Result<(), Errno> {
        record_access(self.path);
        at::unlinkat(&self.root.directory, self.name, AtFlags::empty())
    }
}

pub(super) fn load_store_if_present_under_root(
    root: &WalletStorage,
    path: &Path,
) -> Result<Option<WalletStore>, String> {
    load_store_if_present(&root.bind(path, "wallet store")?)
}

pub(super) fn save_store_under_root(
    root: &WalletStorage,
    path: &Path,
    store: &WalletStore,
) -> Result<(), String> {
    save_store(&root.bind(path, "wallet store")?, store)
}

#[cfg(test)]
fn load_store(path: &Leaf<'_>) -> Result<WalletStore, String> {
    Ok(load_store_if_present(path)?.unwrap_or_default())
}

fn load_store_if_present(path: &Leaf<'_>) -> Result<Option<WalletStore>, String> {
    let Some(bytes) = read_regular_file_if_present(path, "wallet store", MAX_WALLET_STORE_BYTES)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| err.to_string())
}

fn metadata_is_regular_leaf(metadata: &Stat) -> bool {
    FileType::from_raw_mode(metadata.st_mode) == FileType::RegularFile
}

fn same_file(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

/// Each metadata snapshot must show exclusive ownership by the wallet directory.
/// Check both descriptor and path snapshots: either can observe a link change
/// that the other misses during admission or revalidation.
fn ensure_exclusive_wallet_link(snapshots: &[&Stat], label: &str) -> Result<(), String> {
    for metadata in snapshots {
        if metadata.st_nlink != 1 {
            return Err(format!(
                "{label} must be owned by the wallet directory; it has {} hard links",
                metadata.st_nlink
            ));
        }
    }
    Ok(())
}

fn open_regular_file_if_present(path: &Leaf<'_>, label: &str) -> Result<Option<File>, String> {
    let before = match path.stat() {
        Ok(metadata) => metadata,
        Err(Errno::NOENT) => return Ok(None),
        Err(err) => return Err(format!("failed to inspect {label}: {err}")),
    };
    if !metadata_is_regular_leaf(&before) {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    ensure_exclusive_wallet_link(&[&before], label)?;
    let file = path
        .open(OFlags::RDONLY)
        .map_err(|err| format!("failed to open {label}: {err}"))?;
    let opened =
        at::fstat(&file).map_err(|err| format!("failed to inspect open {label}: {err}"))?;
    let after = path
        .stat()
        .map_err(|err| format!("failed to re-inspect {label}: {err}"))?;
    if !metadata_is_regular_leaf(&opened)
        || !metadata_is_regular_leaf(&after)
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return Err(format!("{label} changed while it was being opened"));
    }
    ensure_exclusive_wallet_link(&[&opened, &after], label)?;
    Ok(Some(file))
}

fn verify_open_file_is_current(path: &Leaf<'_>, file: &File, label: &str) -> Result<(), String> {
    let opened = at::fstat(file).map_err(|err| format!("failed to inspect open {label}: {err}"))?;
    let current = path
        .stat()
        .map_err(|err| format!("failed to inspect current {label}: {err}"))?;
    if !metadata_is_regular_leaf(&opened)
        || !metadata_is_regular_leaf(&current)
        || !same_file(&opened, &current)
    {
        return Err(format!("{label} changed during access"));
    }
    ensure_exclusive_wallet_link(&[&opened, &current], label)
}

fn read_limited_file(file: &mut File, label: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    let file_bytes = file
        .metadata()
        .map_err(|err| format!("failed to inspect open {label}: {err}"))?
        .len();
    ensure_size_within_limit(label, file_bytes, max_bytes)?;
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| format!("{label} size limit is invalid"))? as u64;
    let mut bytes = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read {label}: {err}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds the {max_bytes}-byte size limit"));
    }
    Ok(bytes)
}

fn ensure_size_within_limit(label: &str, size: u64, max_bytes: usize) -> Result<(), String> {
    if size > max_bytes as u64 {
        return Err(format!("{label} exceeds the {max_bytes}-byte size limit"));
    }
    Ok(())
}

fn read_regular_file_if_present(
    path: &Leaf<'_>,
    label: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let Some(mut file) = open_regular_file_if_present(path, label)? else {
        return Ok(None);
    };
    let bytes = read_limited_file(&mut file, label, max_bytes)?;
    verify_open_file_is_current(path, &file, label)?;
    Ok(Some(bytes))
}

fn ensure_regular_file_or_absent(path: &Leaf<'_>, label: &str) -> Result<(), String> {
    match path.stat() {
        Ok(metadata) if metadata_is_regular_leaf(&metadata) => {
            ensure_exclusive_wallet_link(&[&metadata], label)
        }
        Ok(_) => Err(format!("{label} must be a regular non-symlink file")),
        Err(Errno::NOENT) => Ok(()),
        Err(err) => Err(format!("failed to inspect {label}: {err}")),
    }
}

fn sync_directory(root: &WalletStorage, label: &str) -> Result<(), String> {
    record_access(&root.path);
    root.directory
        .sync_all()
        .map_err(|err| format!("failed to sync {label}: {err}"))
}

/// Bootstrap may inspect the configured base's ancestors to find the nearest
/// existing directory, open that directory, and create/sync only the missing
/// chain to Wallet. Existing OS aliases above the base are resolved once.
/// Ancestor files and sibling trees are outside this bounded exception.
/// All subsequent effects use the returned directory handle.
pub(super) fn create_wallet_dir_durable(wallet_dir: &Path) -> Result<WalletStorage, String> {
    if !wallet_dir.is_absolute() {
        return Err("wallet storage directory must be an absolute path".to_string());
    }
    let base_path = wallet_dir.ancestors().nth(3).ok_or_else(|| {
        "wallet storage directory must be base_path/ElastOS/SystemServices/Wallet".to_string()
    })?;
    if wallet_dir_for_base(base_path) != wallet_dir
        || wallet_dir
            .components()
            .any(|c| matches!(c, Component::ParentDir))
    {
        return Err(format!(
            "wallet storage directory must be base_path/ElastOS/SystemServices/Wallet: {}",
            wallet_dir.display()
        ));
    }
    let mut existing = base_path;
    let validated = loop {
        match fs::symlink_metadata(existing) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(format!(
                        "wallet storage base directory must be a non-symlink directory: {}",
                        existing.display()
                    ));
                }
                break metadata;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                existing = existing.parent().ok_or_else(|| {
                    "wallet storage base directory has no existing ancestor".to_string()
                })?;
            }
            Err(err) => {
                return Err(format!(
                    "failed to inspect wallet storage base directory: {err}"
                ))
            }
        }
    };
    let canonical = fs::canonicalize(existing)
        .map_err(|err| format!("failed to resolve wallet storage base directory: {err}"))?;
    let directory = at::open(
        &canonical,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|err| format!("failed to open wallet storage base directory: {err}"))?;
    let opened = directory
        .metadata()
        .map_err(|err| format!("failed to inspect open wallet storage base directory: {err}"))?;
    if opened.dev() != validated.dev() || opened.ino() != validated.ino() {
        return Err("wallet storage base directory changed during bootstrap".to_string());
    }
    let mut root = WalletStorage {
        path: existing.to_path_buf(),
        directory,
    };
    for component in wallet_dir.strip_prefix(existing).unwrap().components() {
        let Component::Normal(name) = component else {
            return Err("wallet storage directory contains an invalid component".to_string());
        };
        let path = root.path.join(name);
        // Keep the legacy log for its existing assertions; the independent
        // syscall observer covers the bootstrap ancestor exception as well.
        record_access(&path);
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let directory = match at::openat(&root.directory, name, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => {
                match at::mkdirat(&root.directory, name, Mode::from_raw_mode(0o777)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(err) => {
                        return Err(format!("failed to create wallet storage directory: {err}"))
                    }
                }
                let fd =
                    at::openat(&root.directory, name, flags, Mode::empty()).map_err(|err| {
                        format!("failed to open created wallet storage directory: {err}")
                    })?;
                root.directory.sync_all().map_err(|err| {
                    format!("failed to sync wallet storage parent directory: {err}")
                })?;
                fd
            }
            Err(Errno::LOOP | Errno::NOTDIR) => {
                return Err(format!(
                    "wallet storage ancestor directory must be a non-symlink directory: {}",
                    path.display()
                ))
            }
            Err(err) => return Err(format!("failed to open wallet storage directory: {err}")),
        };
        root = WalletStorage {
            path,
            directory: File::from(directory),
        };
        sync_directory(&root, "wallet storage directory")?;
    }
    sync_directory(&root, "wallet storage directory")?;
    Ok(root)
}

pub(super) fn prune_store(mut store: WalletStore, now: u64) -> WalletStore {
    prune_expired_lifecycles(&mut store, now);
    store
        .challenges
        .retain(|stored| stored.challenge.expires_at > now);
    store
        .bitcoin_challenges
        .retain(|stored| stored.challenge.expires_at > now);
    for request in &mut store.approval_requests {
        expire_approval_if_elapsed(request, now);
    }
    store
        .approval_requests
        .sort_by_key(|request| request.created_at);
    store.approval_requests.reverse();
    let mut retained_resolved_by_principal = std::collections::HashMap::new();
    store.approval_requests.retain(|request| {
        if approval_authority_is_active(request, now) {
            return true;
        }
        let retained = retained_resolved_by_principal
            .entry(request.principal_id.clone())
            .or_insert(0usize);
        if *retained >= MAX_RESOLVED_APPROVAL_HISTORY_PER_PRINCIPAL {
            return false;
        }
        *retained += 1;
        true
    });
    store.approval_requests.reverse();
    store
}

pub(super) fn approval_authority_is_active(request: &WalletApprovalRequest, now: u64) -> bool {
    if matches!(
        request.status,
        ApprovalStatus::Pending | ApprovalStatus::Approved
    ) && request.expires_at > now
    {
        return true;
    }
    request.status == ApprovalStatus::Completed
        && request.intent == "transaction_intent"
        && request.signed_result.is_some()
        && request.validated_chain_outcome.is_none()
}

pub(super) fn prune_expired_lifecycles(store: &mut WalletStore, now: u64) {
    store
        .consumed_lifecycles
        .retain(|record| record.request_expires_at > now);
}

pub(super) fn reject_pre_v2_pending_approvals(store: &mut WalletStore, now: u64) -> usize {
    let mut changed = 0;
    for request in &mut store.approval_requests {
        if matches!(
            request.status,
            ApprovalStatus::Pending | ApprovalStatus::Approved
        ) && (request.session_id.is_empty()
            || request.launch_id.is_empty()
            || request.wallet_request_sha256.is_empty()
            || request.authority_binding.is_empty())
        {
            request.status = ApprovalStatus::Rejected;
            request.resolved_at = Some(now);
            request.rejection_reason = Some(
                "pre-v2 approval preserved as history; a new authority-bound request is required"
                    .to_string(),
            );
            changed += 1;
        }
    }
    changed
}

pub(super) fn expire_approval_if_elapsed(request: &mut WalletApprovalRequest, now: u64) {
    if matches!(
        request.status,
        ApprovalStatus::Pending | ApprovalStatus::Approved
    ) && request.expires_at <= now
    {
        request.status = ApprovalStatus::Expired;
        request.resolved_at = Some(now);
    }
}

fn save_store(path: &Leaf<'_>, store: &WalletStore) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(store).map_err(|err| err.to_string())?;
    ensure_size_within_limit("wallet store", bytes.len() as u64, MAX_WALLET_STORE_BYTES)?;
    ensure_regular_file_or_absent(path, "wallet store")?;
    let tmp_path = path.root.path.join(format!(
        ".{}.{}.{}.tmp",
        path.name.to_string_lossy(),
        std::process::id(),
        rand::thread_rng().next_u64()
    ));
    let tmp = path.root.bind(&tmp_path, "wallet staging store")?;
    let result = (|| {
        let mut file = tmp
            .open(OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)
            .map_err(|err| err.to_string())?;
        at::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|err| err.to_string())?;
        file.write_all(&bytes).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())?;
        ensure_regular_file_or_absent(path, "wallet store")?;
        at::renameat(
            &path.root.directory,
            tmp.name,
            &path.root.directory,
            path.name,
        )
        .map_err(|err| err.to_string())?;
        verify_open_file_is_current(path, &file, "wallet store")?;
        sync_directory(path.root, "wallet store parent directory")?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(err) => match tmp.remove() {
            Ok(()) | Err(Errno::NOENT) => Err(err),
            Err(cleanup_err) => Err(format!(
                "failed to save wallet store: {err}; failed to remove staging store: {cleanup_err}"
            )),
        },
    }
}

pub(super) fn load_or_create_storage_key(root: &WalletStorage) -> Result<[u8; 32], String> {
    let _bootstrap = KEY_BOOTSTRAP_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let key_path = root.path.join(WALLET_KEY_FILE);
    let key_path = root.bind(&key_path, "wallet storage key")?;
    if let Some(key) = read_storage_key_if_present(&key_path)? {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let tmp_path = root.path.join(format!(
        ".{WALLET_KEY_FILE}.{}.{}.tmp",
        std::process::id(),
        rand::thread_rng().next_u64()
    ));
    let tmp = root.bind(&tmp_path, "wallet staging key")?;
    let staged = (|| {
        let mut file = tmp
            .open(OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)
            .map_err(|err| err.to_string())?;
        at::fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|err| err.to_string())?;
        file.write_all(hex::encode(key).as_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(b"\n").map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())
    })();
    if let Err(err) = staged {
        return match tmp.remove() {
            Ok(()) | Err(Errno::NOENT) => Err(err),
            Err(cleanup_err) => Err(format!(
                "failed to stage wallet storage key: {err}; failed to remove staging key: {cleanup_err}"
            )),
        };
    }
    record_access(key_path.path);
    match at::linkat(&root.directory, tmp.name, &root.directory, key_path.name, AtFlags::empty()) {
        Ok(()) => {
            sync_directory(root, "wallet storage directory")?;
            tmp.remove().map_err(|err| err.to_string())?;
            sync_directory(root, "wallet storage directory")?;
            let installed = read_storage_key(&key_path)?;
            if installed != key {
                return Err("wallet storage key changed during installation".to_string());
            }
            Ok(installed)
        }
        Err(Errno::EXIST) => {
            tmp.remove().map_err(|err| err.to_string())?;
            sync_directory(root, "wallet storage directory")?;
            read_storage_key(&key_path)
        }
        Err(err) => match tmp.remove() {
            Ok(()) => Err(err.to_string()),
            Err(cleanup_err) => Err(format!(
                "failed to install wallet storage key: {err}; failed to remove staging key: {cleanup_err}"
            )),
        },
    }
}

fn read_storage_key(key_path: &Leaf<'_>) -> Result<[u8; 32], String> {
    read_storage_key_if_present(key_path)?
        .ok_or_else(|| "wallet storage key does not exist".to_string())
}

fn read_storage_key_if_present(key_path: &Leaf<'_>) -> Result<Option<[u8; 32]>, String> {
    let Some(mut file) = open_regular_file_if_present(key_path, "wallet storage key")? else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        let mut permissions = file
            .metadata()
            .map_err(|err| format!("failed to inspect wallet storage key mode: {err}"))?
            .permissions();
        if permissions.mode() & 0o7777 != 0o600 {
            permissions.set_mode(0o600);
            file.set_permissions(permissions)
                .map_err(|err| format!("failed to repair wallet storage key mode: {err}"))?;
            file.sync_all()
                .map_err(|err| format!("failed to sync repaired wallet storage key: {err}"))?;
        }
    }
    let value = String::from_utf8(read_limited_file(
        &mut file,
        "wallet storage key",
        MAX_WALLET_STORAGE_KEY_BYTES,
    )?)
    .map_err(|err| format!("wallet storage key must be UTF-8 text: {err}"))?;
    verify_open_file_is_current(key_path, &file, "wallet storage key")?;
    sync_directory(key_path.root, "wallet storage directory")?;
    let bytes = hex::decode(value.trim()).map_err(|err| err.to_string())?;
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| "wallet storage key must be 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(path: &Path) -> WalletStorage {
        WalletStorage {
            path: path.to_path_buf(),
            directory: File::open(path).unwrap(),
        }
    }

    #[cfg(unix)]
    fn assert_revalidation_rejects_link_change(remove_link: bool) {
        use crate::tests::io_observer::LinkRace;

        for (filename, label, reason) in [
            (
                WALLET_KEY_FILE,
                "wallet storage key",
                "wallet storage key must be owned by the wallet directory; it has 2 hard links",
            ),
            (
                "wallet-state.json",
                "wallet store",
                "wallet store must be owned by the wallet directory; it has 2 hard links",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let wallet = dir.path().join("wallet");
            fs::create_dir(&wallet).unwrap();
            let path = wallet.join(filename);
            fs::write(&path, b"synthetic wallet state").unwrap();
            let outside = dir.path().join(filename);
            if remove_link {
                fs::hard_link(&path, &outside).unwrap();
            }
            let root = test_root(&wallet);
            let leaf = root.bind(&path, label).unwrap();
            let file = File::open(&path).unwrap();
            let linked_path = path.clone();
            let race = LinkRace::begin(&path, move || {
                if remove_link {
                    fs::remove_file(outside).unwrap();
                } else {
                    fs::hard_link(linked_path, outside).unwrap();
                }
            });
            let result = verify_open_file_is_current(&leaf, &file, label);
            race.finish(if remove_link { 2 } else { 1 });
            assert_eq!(result.unwrap_err(), reason);
            assert_eq!(
                fs::metadata(&path).unwrap().nlink(),
                if remove_link { 1 } else { 2 }
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn wallet_revalidation_rejects_link_added_after_fstat() {
        if crate::tests::io_observer::run_observed_child(
            "storage::tests::wallet_revalidation_rejects_link_added_after_fstat",
        ) {
            return;
        }
        assert_revalidation_rejects_link_change(false);
    }

    #[cfg(unix)]
    #[test]
    fn wallet_revalidation_rejects_link_removed_after_fstat() {
        if crate::tests::io_observer::run_observed_child(
            "storage::tests::wallet_revalidation_rejects_link_removed_after_fstat",
        ) {
            return;
        }
        assert_revalidation_rejects_link_change(true);
    }

    #[test]
    fn storage_key_bootstrap_is_private_atomic_and_concurrent() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().to_path_buf());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let threads = (0..12)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_storage_key(&test_root(path.as_ref()))
                })
            })
            .collect::<Vec<_>>();
        let keys = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>();

        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>(),
            vec![std::ffi::OsString::from(WALLET_KEY_FILE)]
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(dir.path().join(WALLET_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn wallet_store_is_atomic_private_and_size_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet-state.json");
        let mut store = WalletStore::default();
        store.default_accounts.push(DefaultWalletAccount {
            schema: "elastos.wallet.default_account/v1".to_string(),
            principal_id: "person:local:alice".to_string(),
            chain_namespace: "eip155:20".to_string(),
            intent: "browser_personal_sign".to_string(),
            account_id: "wallet:eip155:20:test".to_string(),
            set_at: 1,
        });
        let root = test_root(dir.path());
        let leaf = root.bind(&path, "wallet store").unwrap();
        save_store(&leaf, &store).unwrap();
        assert_eq!(load_store(&leaf).unwrap().default_accounts.len(), 1);
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );

        let oversized = dir.path().join("oversized.json");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_WALLET_STORE_BYTES as u64 + 1)
            .unwrap();
        assert!(load_store(&root.bind(&oversized, "wallet store").unwrap())
            .unwrap_err()
            .contains("67108864-byte size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn wallet_storage_rejects_symlink_leafs_without_touching_targets() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let external_store = dir.path().join("external-state.json");
        let external_bytes = serde_json::to_vec_pretty(&WalletStore::default()).unwrap();
        fs::write(&external_store, &external_bytes).unwrap();
        let store_path = dir.path().join("wallet-state.json");
        symlink(&external_store, &store_path).unwrap();
        let root = test_root(dir.path());
        let leaf = root.bind(&store_path, "wallet store").unwrap();
        assert!(load_store(&leaf)
            .unwrap_err()
            .contains("regular non-symlink file"));
        assert!(save_store(&leaf, &WalletStore::default())
            .unwrap_err()
            .contains("regular non-symlink file"));
        assert_eq!(fs::read(&external_store).unwrap(), external_bytes);

        let wallet_dir = dir.path().join("wallet");
        fs::create_dir(&wallet_dir).unwrap();
        let external_key = dir.path().join("external-key.hex");
        let external_key_contents = format!("{}\n", "ab".repeat(32));
        fs::write(&external_key, &external_key_contents).unwrap();
        symlink(&external_key, wallet_dir.join(WALLET_KEY_FILE)).unwrap();
        assert!(load_or_create_storage_key(&test_root(&wallet_dir))
            .unwrap_err()
            .contains("regular non-symlink file"));
        assert_eq!(
            fs::read_to_string(&external_key).unwrap(),
            external_key_contents
        );
    }

    #[test]
    fn wallet_directory_bootstrap_creates_the_full_durable_leaf_chain() {
        let dir = tempfile::tempdir().unwrap();
        let wallet_dir = dir
            .path()
            .join("ElastOS")
            .join("SystemServices")
            .join("Wallet");

        create_wallet_dir_durable(&wallet_dir).unwrap();
        create_wallet_dir_durable(&wallet_dir).unwrap();
        assert!(wallet_dir.is_dir());
    }
}
