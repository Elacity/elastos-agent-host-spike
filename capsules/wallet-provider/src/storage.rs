use super::*;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_WALLET_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_WALLET_STORAGE_KEY_BYTES: usize = 128;

pub(super) fn load_store(path: &Path) -> Result<WalletStore, String> {
    Ok(load_store_if_present(path)?.unwrap_or_default())
}

pub(super) fn load_store_if_present(path: &Path) -> Result<Option<WalletStore>, String> {
    let Some(bytes) = read_regular_file_if_present(path, "wallet store", MAX_WALLET_STORE_BYTES)?
    else {
        return Ok(None);
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|err| err.to_string())
}

fn metadata_is_regular_leaf(metadata: &Metadata) -> bool {
    metadata.file_type().is_file() && !metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(_left: &Metadata, _right: &Metadata) -> bool {
    true
}

fn open_regular_file_if_present(path: &Path, label: &str) -> Result<Option<File>, String> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("failed to inspect {label}: {err}")),
    };
    if !metadata_is_regular_leaf(&before) {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|err| format!("failed to open {label}: {err}"))?;
    let opened = file
        .metadata()
        .map_err(|err| format!("failed to inspect open {label}: {err}"))?;
    let after =
        fs::symlink_metadata(path).map_err(|err| format!("failed to re-inspect {label}: {err}"))?;
    if !metadata_is_regular_leaf(&opened)
        || !metadata_is_regular_leaf(&after)
        || !same_file(&before, &opened)
        || !same_file(&opened, &after)
    {
        return Err(format!("{label} changed while it was being opened"));
    }
    Ok(Some(file))
}

fn verify_open_file_is_current(path: &Path, file: &File, label: &str) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|err| format!("failed to inspect open {label}: {err}"))?;
    let current = fs::symlink_metadata(path)
        .map_err(|err| format!("failed to inspect current {label}: {err}"))?;
    if !metadata_is_regular_leaf(&opened)
        || !metadata_is_regular_leaf(&current)
        || !same_file(&opened, &current)
    {
        return Err(format!("{label} changed during access"));
    }
    Ok(())
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
    path: &Path,
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

fn ensure_regular_file_or_absent(path: &Path, label: &str) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_regular_leaf(&metadata) => Ok(()),
        Ok(_) => Err(format!("{label} must be a regular non-symlink file")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to inspect {label}: {err}")),
    }
}

fn ensure_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|err| format!("failed to inspect {label}: {err}"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{label} must be a non-symlink directory"));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path, label: &str) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|err| format!("failed to sync {label}: {err}"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path, _label: &str) -> Result<(), String> {
    Ok(())
}

pub(super) fn create_wallet_dir_durable(wallet_dir: &Path) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut cursor = wallet_dir;
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                    return Err(format!(
                        "wallet storage directory component must be a non-symlink directory: {}",
                        cursor.display()
                    ));
                }
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| "wallet storage directory has no existing parent".to_string())?;
            }
            Err(err) => {
                return Err(format!(
                    "failed to inspect wallet storage directory {}: {err}",
                    cursor.display()
                ))
            }
        }
    }

    fs::create_dir_all(wallet_dir)
        .map_err(|err| format!("failed to create wallet storage directory: {err}"))?;
    for directory in missing.iter().rev() {
        ensure_directory(directory, "wallet storage directory")?;
        sync_directory(directory, "wallet storage directory")?;
        let parent = directory
            .parent()
            .ok_or_else(|| "wallet storage directory has no parent to synchronize".to_string())?;
        ensure_directory(parent, "wallet storage parent directory")?;
        sync_directory(parent, "wallet storage parent directory")?;
    }
    ensure_directory(wallet_dir, "wallet storage directory")?;
    sync_directory(wallet_dir, "wallet storage directory")?;
    let parent = wallet_dir
        .parent()
        .ok_or_else(|| "wallet storage directory has no parent to synchronize".to_string())?;
    ensure_directory(parent, "wallet storage parent directory")?;
    sync_directory(parent, "wallet storage parent directory")
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

pub(super) fn save_store(path: &Path, store: &WalletStore) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(store).map_err(|err| err.to_string())?;
    ensure_size_within_limit("wallet store", bytes.len() as u64, MAX_WALLET_STORE_BYTES)?;
    let parent = path
        .parent()
        .ok_or_else(|| "wallet store path has no parent directory".to_string())?;
    ensure_directory(parent, "wallet store parent directory")?;
    ensure_regular_file_or_absent(path, "wallet store")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "wallet store path has an invalid file name".to_string())?;
    let tmp = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        rand::thread_rng().next_u64()
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        {
            let mut permissions = file
                .metadata()
                .map_err(|err| err.to_string())?
                .permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)
                .map_err(|err| err.to_string())?;
        }
        file.write_all(&bytes).map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())?;
        ensure_regular_file_or_absent(path, "wallet store")?;
        fs::rename(&tmp, path).map_err(|err| err.to_string())?;
        verify_open_file_is_current(path, &file, "wallet store")?;
        sync_directory(parent, "wallet store parent directory")?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(err) => match fs::remove_file(&tmp) {
            Ok(()) => Err(err),
            Err(cleanup_err) if cleanup_err.kind() == std::io::ErrorKind::NotFound => Err(err),
            Err(cleanup_err) => Err(format!(
                "failed to save wallet store: {err}; failed to remove staging store: {cleanup_err}"
            )),
        },
    }
}

pub(super) fn load_or_create_storage_key(wallet_dir: &Path) -> Result<[u8; 32], String> {
    ensure_directory(wallet_dir, "wallet storage directory")?;
    let key_path = wallet_dir.join(WALLET_KEY_FILE);
    if let Some(key) = read_storage_key_if_present(&key_path)? {
        return Ok(key);
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    let tmp = wallet_dir.join(format!(
        ".{WALLET_KEY_FILE}.{}.{}.tmp",
        std::process::id(),
        rand::thread_rng().next_u64()
    ));
    let staged = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        {
            let mut permissions = file
                .metadata()
                .map_err(|err| err.to_string())?
                .permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions)
                .map_err(|err| err.to_string())?;
        }
        file.write_all(hex::encode(key).as_bytes())
            .map_err(|err| err.to_string())?;
        file.write_all(b"\n").map_err(|err| err.to_string())?;
        file.sync_all().map_err(|err| err.to_string())
    })();
    if let Err(err) = staged {
        return match fs::remove_file(&tmp) {
            Ok(()) => Err(err),
            Err(cleanup_err) if cleanup_err.kind() == std::io::ErrorKind::NotFound => Err(err),
            Err(cleanup_err) => Err(format!(
                "failed to stage wallet storage key: {err}; failed to remove staging key: {cleanup_err}"
            )),
        };
    }
    match fs::hard_link(&tmp, &key_path) {
        Ok(()) => {
            sync_directory(wallet_dir, "wallet storage directory")?;
            fs::remove_file(&tmp).map_err(|err| err.to_string())?;
            sync_directory(wallet_dir, "wallet storage directory")?;
            let installed = read_storage_key(&key_path)?;
            if installed != key {
                return Err("wallet storage key changed during installation".to_string());
            }
            Ok(installed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            fs::remove_file(&tmp).map_err(|remove_err| remove_err.to_string())?;
            sync_directory(wallet_dir, "wallet storage directory")?;
            read_storage_key(&key_path)
        }
        Err(err) => {
            let cleanup = fs::remove_file(&tmp);
            match cleanup {
                Ok(()) => Err(err.to_string()),
                Err(cleanup_err) => Err(format!(
                    "failed to install wallet storage key: {err}; failed to remove staging key: {cleanup_err}"
                )),
            }
        }
    }
}

fn read_storage_key(key_path: &Path) -> Result<[u8; 32], String> {
    read_storage_key_if_present(key_path)?
        .ok_or_else(|| "wallet storage key does not exist".to_string())
}

fn read_storage_key_if_present(key_path: &Path) -> Result<Option<[u8; 32]>, String> {
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
    let wallet_dir = key_path
        .parent()
        .ok_or_else(|| "wallet storage key path has no parent directory".to_string())?;
    sync_directory(wallet_dir, "wallet storage directory")?;
    let bytes = hex::decode(value.trim()).map_err(|err| err.to_string())?;
    bytes
        .try_into()
        .map(Some)
        .map_err(|_| "wallet storage key must be 32 bytes".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    load_or_create_storage_key(path.as_ref())
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
        save_store(&path, &store).unwrap();
        assert_eq!(load_store(&path).unwrap().default_accounts.len(), 1);
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
        assert!(load_store(&oversized)
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
        assert!(load_store(&store_path)
            .unwrap_err()
            .contains("regular non-symlink file"));
        assert!(save_store(&store_path, &WalletStore::default())
            .unwrap_err()
            .contains("regular non-symlink file"));
        assert_eq!(fs::read(&external_store).unwrap(), external_bytes);

        let wallet_dir = dir.path().join("wallet");
        fs::create_dir(&wallet_dir).unwrap();
        let external_key = dir.path().join("external-key.hex");
        let external_key_contents = format!("{}\n", "ab".repeat(32));
        fs::write(&external_key, &external_key_contents).unwrap();
        symlink(&external_key, wallet_dir.join(WALLET_KEY_FILE)).unwrap();
        assert!(load_or_create_storage_key(&wallet_dir)
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

/// Unit tests for the wallet store's own refusals, approval order and expiry.
///
/// They pin answers the store already gives; they add no rule and register no
/// falsifier. They prove the store, not confinement: the Runtime decides whether
/// the provider runs at all, and no test here speaks for that decision.
///
/// The `wallet store path has no parent directory` arm is deliberately deferred
/// here rather than chased: the provider always hands the store an absolute path
/// under its wallet directory, and a bare `/` reaches that arm without showing
/// anything about a real store.
#[cfg(test)]
mod uf_tests {
    use super::*;

    fn sample_request(id: u64, principal: &str, now: u64) -> WalletApprovalRequest {
        serde_json::from_value(serde_json::json!({
            "schema": "elastos.wallet.approval_request/v1",
            "request_id": format!("req-{id}"),
            "wallet_request_sha256": format!("sha-{id}"),
            "authority_binding": format!("binding-{id}"),
            "kind": "signature",
            "status": "pending",
            "principal_id": principal,
            "account_id": "wallet:eip155:20:req",
            "proof_binding_id": "proof:eip155:20:req",
            "chain_namespace": "eip155:20",
            "address": "0x0000000000000000000000000000000000000000",
            "intent": "browser_personal_sign",
            "session_id": format!("session-{id}"),
            "launch_id": format!("launch-{id}"),
            "requested_by_actor": "browser",
            "resource": "elastos://wallet/eip155:20/sign/browser_personal_sign",
            "reason": "unit test request",
            "payload": { "message": format!("message-{id}") },
            "payload_hash": format!("hash-{id}"),
            "created_at": now,
            "expires_at": now + 1_000,
        }))
        .expect("the sample approval request must decode")
    }

    /// Falsifier: swallow the parse failure and answer `Ok(None)`, so a
    /// corrupted store reads as a missing one and the reason is lost.
    #[test]
    fn load_store_if_present_rejects_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet-state.json");
        fs::write(&path, b"{ not valid json").unwrap();
        let reason = "key must be a string at line 1 column 3";
        assert_eq!(load_store_if_present(&path).unwrap_err(), reason);
        assert_eq!(load_store(&path).unwrap_err(), reason);
    }

    /// Falsifier: create the missing parent inside `save_store`; the refusal
    /// never fires and the save succeeds.
    #[test]
    fn save_store_refuses_when_parent_directory_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing").join("wallet-state.json");
        assert!(save_store(&path, &WalletStore::default())
            .unwrap_err()
            .starts_with("failed to inspect wallet store parent directory"));
    }

    /// Falsifier: accept `size >= max_bytes`, so the exact limit is refused.
    #[test]
    fn ensure_size_within_limit_boundaries() {
        assert!(ensure_size_within_limit(
            "wallet store",
            MAX_WALLET_STORE_BYTES as u64,
            MAX_WALLET_STORE_BYTES
        )
        .is_ok());
        assert!(ensure_size_within_limit("wallet store", 0, MAX_WALLET_STORE_BYTES).is_ok());
    }

    /// Falsifier: accept any existing path in `ensure_directory`, so a regular
    /// file passes as the wallet directory.
    #[test]
    fn ensure_directory_rejects_regular_file_and_accepts_dir() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-dir");
        fs::create_dir(&real).unwrap();
        assert!(ensure_directory(&real, "wallet storage directory").is_ok());
        let file = dir.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            ensure_directory(&file, "wallet storage directory").unwrap_err(),
            "wallet storage directory must be a non-symlink directory"
        );
    }

    /// Falsifier: let `create_wallet_dir_durable` fall through to
    /// `create_dir_all` instead of refusing a regular file component.
    #[test]
    fn create_wallet_dir_durable_refuses_file_component() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("blocker");
        fs::write(&file, b"x").unwrap();
        assert_eq!(
            create_wallet_dir_durable(&file).unwrap_err(),
            format!(
                "wallet storage directory component must be a non-symlink directory: {}",
                file.display()
            )
        );
    }

    /// `prune_store` keeps the newest resolved history, then answers oldest
    /// first: the final `reverse` at the end of the function is what puts the
    /// kept list back in `created_at` order.
    ///
    /// Falsifier: drop the final `reverse`, and the answer becomes newest first;
    /// drop the `sort_by_key`, and the answer keeps the input order.
    #[test]
    fn prune_store_sorts_oldest_first() {
        let mut store = WalletStore::default();
        store
            .approval_requests
            .push(sample_request(1, "person:local:alice", 1));
        store
            .approval_requests
            .push(sample_request(2, "person:local:alice", 50));
        store
            .approval_requests
            .push(sample_request(3, "person:local:alice", 20));
        let order = prune_store(store, 0)
            .approval_requests
            .iter()
            .map(|request| request.created_at)
            .collect::<Vec<_>>();
        assert_eq!(order, vec![1, 20, 50]);
    }

    /// Falsifier: stamp `resolved_at` on every call instead of only when the
    /// request first elapses, and the second call moves the time.
    #[test]
    fn expire_approval_if_elapsed_sets_expired_once() {
        let mut request = sample_request(1, "person:local:alice", 0);
        request.expires_at = 5;
        expire_approval_if_elapsed(&mut request, 10);
        assert_eq!(request.status, ApprovalStatus::Expired);
        assert_eq!(request.resolved_at, Some(10));
        expire_approval_if_elapsed(&mut request, 20);
        assert_eq!(request.resolved_at, Some(10));
    }

    /// Falsifier: treat every `Completed` request as active whatever its
    /// signature or Chain outcome, or treat an elapsed pending request as
    /// active; one of the three cases below flips.
    #[test]
    fn approval_authority_is_active_refuses_resolved_requests() {
        let now = 1_000;

        let mut expired_pending = sample_request(1, "person:local:alice", now);
        expired_pending.expires_at = now;
        assert!(!approval_authority_is_active(&expired_pending, now));

        let mut recorded = sample_request(2, "person:local:alice", now);
        recorded.status = ApprovalStatus::Completed;
        recorded.intent = "transaction_intent".to_string();
        recorded.signed_result = Some(serde_json::json!({ "signed_transaction": "0x0202" }));
        recorded.validated_chain_outcome = Some(
            serde_json::from_value(serde_json::json!({
                "schema": "elastos.wallet.validated-chain-outcome/v1",
                "approval_request_id": "req-2",
                "account_id": "wallet:eip155:20:req",
                "chain_namespace": "eip155:20",
                "network": "esc-mainnet",
                "binding": {
                    "kind": "managed_signed",
                    "signed_transaction_sha256": "sha256:0202",
                },
                "transaction_hash": "0x0202",
                "chain_observation": { "schema": "elastos.chain.broadcast_receipt/v1" },
                "confirmed_at": 1_000,
            }))
            .expect("the sample Chain outcome must decode"),
        );
        assert!(!approval_authority_is_active(&recorded, now));

        let mut unsigned = sample_request(3, "person:local:alice", now);
        unsigned.status = ApprovalStatus::Completed;
        unsigned.intent = "transaction_intent".to_string();
        assert!(!approval_authority_is_active(&unsigned, now));
    }
}

/// Unit tests for the storage key the wallet provider accepts at `init` and
/// the bootstrap refusals around it.
///
/// One test per refusal: each asserts the whole `Err`, never a prefix and never
/// `is_err()` alone. They pin answers the provider already gives; they add no
/// rule and register no falsifier. They prove what this provider refuses, not
/// confinement: the Runtime decides whether the provider runs at all, and no
/// test here speaks for that decision.
///
/// Every case builds a fresh `tempfile::tempdir()`, so the wallet store's own
/// files never reach a real Home.
#[cfg(test)]
mod uf_storage_key_refusal_tests {
    use super::*;

    /// Restore a fixture's original permissions before assertions or on unwind.
    #[cfg(unix)]
    struct ModeGuard<'a> {
        path: &'a Path,
        original: Option<fs::Permissions>,
    }

    #[cfg(unix)]
    impl<'a> ModeGuard<'a> {
        fn set(path: &'a Path, mode: u32) -> Self {
            let guard = Self {
                path,
                original: Some(fs::metadata(path).unwrap().permissions()),
            };
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            guard
        }

        fn restore(&mut self) -> std::io::Result<()> {
            if let Some(original) = &self.original {
                fs::set_permissions(self.path, original.clone())?;
                self.original = None;
            }
            Ok(())
        }
    }

    #[cfg(unix)]
    impl Drop for ModeGuard<'_> {
        fn drop(&mut self) {
            // Preserve the original panic if cleanup also fails during unwind.
            let _ = self.restore();
        }
    }

    /// The same 32 bytes in the form `load_or_create_storage_key` writes them:
    /// 64 hex characters and a newline.
    fn key_text() -> String {
        format!("{}\n", "ab".repeat(32))
    }

    /// One temporary wallet directory that holds a `wallet-key.hex` of the
    /// given text and mode, and the key's path.
    #[cfg(unix)]
    fn key_dir_with(text: &[u8], mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        fs::write(&key_path, text).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(mode)).unwrap();
        (dir, key_path)
    }

    /// Falsifier: use `Ok(read_storage_key_if_present(key_path)?.unwrap_or([0; 32]))`
    /// for a missing key instead of refusing it.
    /// `read_storage_key` is the arm `load_or_create_storage_key` skips over
    /// when a key is absent, so a missing key must be named, not invented.
    #[test]
    fn read_storage_key_refuses_a_missing_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        assert_eq!(
            read_storage_key(&key_path).unwrap_err(),
            "wallet storage key does not exist"
        );
    }

    /// Falsifier: accept a decoded key of any length, so a 31-byte key is
    /// trusted with the store it reloads at `init`. The fixture is 62 hex
    /// characters, which decode to 31 bytes; 31 characters would stop at the
    /// hex refusal instead.
    #[test]
    fn read_storage_key_refuses_a_key_that_is_not_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        fs::write(&key_path, format!("{}\n", "ab".repeat(31))).unwrap();
        assert_eq!(
            read_storage_key(&key_path).unwrap_err(),
            "wallet storage key must be 32 bytes"
        );
    }

    /// Falsifier: decode the key text without reporting the decoder's own
    /// error, so an odd-length key loses the reason it was refused. Three hex
    /// characters are odd, so the decoder refuses before the 32-byte check.
    #[test]
    fn read_storage_key_refuses_odd_length_hex_text() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        fs::write(&key_path, b"abc\n").unwrap();
        let reason = hex::decode("abc").unwrap_err().to_string();
        assert_eq!(read_storage_key(&key_path).unwrap_err(), reason);
    }

    /// Falsifier: map a decoder error to a fixed message, so a key with a
    /// character outside the hex alphabet is refused for the wrong reason.
    #[test]
    fn read_storage_key_refuses_a_character_outside_the_hex_alphabet() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        let text = "zz".repeat(32);
        fs::write(&key_path, format!("{text}\n")).unwrap();
        let reason = hex::decode(&text).unwrap_err().to_string();
        assert_eq!(read_storage_key(&key_path).unwrap_err(), reason);
    }

    /// Falsifier: read the key bytes as text without checking, so a key file
    /// holding a non-UTF-8 byte is decoded from a lossy string.
    #[test]
    fn read_storage_key_refuses_a_key_that_is_not_utf8_text() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join(WALLET_KEY_FILE);
        fs::write(&key_path, [0xff]).unwrap();
        let reason = String::from_utf8(vec![0xff]).unwrap_err();
        assert_eq!(
            read_storage_key(&key_path).unwrap_err(),
            format!("wallet storage key must be UTF-8 text: {reason}")
        );
    }

    /// Falsifier: let `read_limited_file` compute `max_bytes + 1` without
    /// checking, so `usize::MAX` panics with overflow checks or wraps to zero
    /// without them, making the read limit zero.
    /// `usize::MAX.checked_add(1)` is `None`, which is the one input that
    /// reaches this arm.
    #[test]
    fn read_limited_file_refuses_an_invalid_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet-state.json");
        fs::write(&path, b"{}").unwrap();
        let mut file = File::open(&path).unwrap();
        assert_eq!(
            read_limited_file(&mut file, "wallet store", usize::MAX).unwrap_err(),
            "wallet store size limit is invalid"
        );
    }

    /// Falsifier: treat a path inside a directory the process cannot search as
    /// absent, so an unreadable directory reads as a missing wallet store.
    /// The leaf checks never run: `symlink_metadata` fails `EACCES` first.
    #[cfg(unix)]
    #[test]
    fn open_regular_file_if_present_refuses_a_path_it_cannot_inspect() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let path = locked.join("wallet-state.json");
        fs::write(&path, b"{}").unwrap();
        let mut mode = ModeGuard::set(&locked, 0o000);
        let reason = fs::symlink_metadata(&path).unwrap_err();
        let refused = load_store_if_present(&path);
        mode.restore().unwrap();
        assert_eq!(
            refused.unwrap_err(),
            format!("failed to inspect wallet store: {reason}")
        );
    }

    /// Falsifier: return `Ok(())` for a path the process cannot inspect, so an
    /// unreadable parent reads as a missing wallet store and a save proceeds
    /// over it. This is the `ensure_regular_file_or_absent` arm, whose leaf
    /// refusal the symlink tests already pin.
    #[cfg(unix)]
    #[test]
    fn ensure_regular_file_or_absent_refuses_a_path_it_cannot_inspect() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let path = locked.join("wallet-state.json");
        let mut mode = ModeGuard::set(&locked, 0o000);
        let reason = fs::symlink_metadata(&path).unwrap_err();
        let refused = ensure_regular_file_or_absent(&path, "wallet store");
        mode.restore().unwrap();
        assert_eq!(
            refused.unwrap_err(),
            format!("failed to inspect wallet store: {reason}")
        );
    }

    /// Falsifier: return `Ok(())` for a directory the process cannot inspect,
    /// so a wallet directory whose parent cannot be searched reads as a
    /// verified directory. This is the `ensure_directory` arm; its
    /// non-symlink refusal is already pinned by `mod uf_tests`.
    #[cfg(unix)]
    #[test]
    fn ensure_directory_refuses_a_path_it_cannot_inspect() {
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let wallet_dir = locked.join("Wallet");
        fs::create_dir(&wallet_dir).unwrap();
        let mut mode = ModeGuard::set(&locked, 0o000);
        let reason = fs::symlink_metadata(&wallet_dir).unwrap_err();
        let refused = ensure_directory(&wallet_dir, "wallet storage directory");
        mode.restore().unwrap();
        assert_eq!(
            refused.unwrap_err(),
            format!("failed to inspect wallet storage directory: {reason}")
        );
    }

    /// Falsifier: return `Ok(None)` when `open` fails, so an unreadable key
    /// reads as a missing one and `init` mints a fresh key over it. The leaf
    /// checks pass here: the file is a regular non-symlink file at `0o000`, so
    /// the refusal must come from `open`, not from the leaf check a symlink
    /// case reaches.
    #[cfg(unix)]
    #[test]
    fn open_regular_file_if_present_refuses_a_file_it_cannot_open() {
        let (_dir, key_path) = key_dir_with(key_text().as_bytes(), 0o600);
        let mut mode = ModeGuard::set(&key_path, 0o000);
        let reason = File::open(&key_path).unwrap_err();
        let refused = read_storage_key_if_present(&key_path);
        mode.restore().unwrap();
        assert_eq!(
            refused.unwrap_err(),
            format!("failed to open wallet storage key: {reason}")
        );
    }

    /// Falsifier: report a wallet directory path whose component runs under a
    /// regular file as a missing directory, so a path like `<file>/Wallet`
    /// bootstraps over the file. This is the inspection arm; the path handed in
    /// is the joined one, not the file, so the component check never sees it.
    #[cfg(unix)]
    #[test]
    fn create_wallet_dir_durable_refuses_a_path_it_cannot_inspect() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, b"x").unwrap();
        let wallet_dir = blocker.join("Wallet");
        let reason = fs::symlink_metadata(&wallet_dir).unwrap_err();
        assert_eq!(
            create_wallet_dir_durable(&wallet_dir).unwrap_err(),
            format!(
                "failed to inspect wallet storage directory {}: {reason}",
                wallet_dir.display()
            )
        );
    }

    /// Falsifier: answer `Ok(())` when `create_dir_all` fails, so a wallet
    /// directory that cannot be created reads as created and the key write
    /// reports the wrong fault. The parent stays searchable but unwritable.
    #[cfg(unix)]
    #[test]
    fn create_wallet_dir_durable_refuses_a_directory_it_cannot_create() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let wallet_dir = parent.join("Wallet");
        let mut mode = ModeGuard::set(&parent, 0o500);
        let reason = fs::create_dir(&wallet_dir).unwrap_err();
        let refused = create_wallet_dir_durable(&wallet_dir);
        mode.restore().unwrap();
        assert_eq!(
            refused.unwrap_err(),
            format!("failed to create wallet storage directory: {reason}")
        );
    }

    /// Falsifier: replace `wallet storage directory has no existing parent`
    /// with `Ok(())`, so the loop continues with a path that has no parent and
    /// the bootstrap answers success for a directory it never inspected.
    ///
    /// The empty path is the one input that reaches the arm: only `/` and `""`
    /// have no parent, `/` passes the directory check and would sync the volume
    /// root, and `""` fails `symlink_metadata` with `ENOENT`, so it is pushed as
    /// missing and its parent is `None`.
    #[test]
    fn create_wallet_dir_durable_refuses_a_path_with_no_existing_parent() {
        assert_eq!(
            create_wallet_dir_durable(Path::new("")).unwrap_err(),
            "wallet storage directory has no existing parent"
        );
    }

    /// Falsifier: accept a handle without checking the path still names the
    /// same file, so a key replaced between open and use is trusted. A path
    /// removed after open reaches this arm directly.
    #[test]
    fn verify_open_file_is_current_refuses_a_removed_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(WALLET_KEY_FILE);
        fs::write(&path, key_text()).unwrap();
        let file = File::open(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let reason = fs::symlink_metadata(&path).unwrap_err();
        assert_eq!(
            verify_open_file_is_current(&path, &file, "wallet storage key").unwrap_err(),
            format!("failed to inspect current wallet storage key: {reason}")
        );
    }

    /// Falsifier: compare only the leaf type, so a handle for one file is
    /// accepted as the file the path now names. Two files in one directory
    /// have different inodes, which is what this arm compares.
    #[test]
    fn verify_open_file_is_current_refuses_a_different_file() {
        let dir = tempfile::tempdir().unwrap();
        let opened_path = dir.path().join("opened.hex");
        let current_path = dir.path().join("current.hex");
        fs::write(&opened_path, key_text()).unwrap();
        fs::write(&current_path, key_text()).unwrap();
        let file = File::open(&opened_path).unwrap();
        assert_eq!(
            verify_open_file_is_current(&current_path, &file, "wallet storage key").unwrap_err(),
            "wallet storage key changed during access"
        );
    }

    /// Falsifier: read the bytes without checking the handle is readable, so a
    /// write-only handle answers an empty key. `write` without `read` opens
    /// fine and fails at the first read.
    #[test]
    fn read_limited_file_refuses_a_handle_it_cannot_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wallet-state.json");
        fs::write(&path, b"{}").unwrap();
        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        let reason = file.read_to_end(&mut Vec::new()).unwrap_err();
        assert_eq!(
            read_limited_file(&mut file, "wallet store", MAX_WALLET_STORE_BYTES).unwrap_err(),
            format!("failed to read wallet store: {reason}")
        );
    }

    /// Falsifier: answer `Ok(())` when the directory cannot be opened, so a
    /// wallet directory that was never synced reads as durable.
    #[cfg(unix)]
    #[test]
    fn sync_directory_refuses_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");
        let reason = File::open(&missing).unwrap_err();
        assert_eq!(
            sync_directory(&missing, "wallet storage directory").unwrap_err(),
            format!("failed to sync wallet storage directory: {reason}")
        );
    }

    /// The mode repair itself, not a string: a `wallet-key.hex` that any user
    /// can read is repaired to `0o600` and the same 32 bytes come back. No
    /// test reached this branch before; `mod tests` asserts `0o600` after
    /// creation only.
    ///
    /// Falsifier: drop the repair block, so the loaded key keeps `0o644`.
    #[cfg(unix)]
    #[test]
    fn read_storage_key_if_present_repairs_a_loose_key_mode() {
        let (_dir, key_path) = key_dir_with(key_text().as_bytes(), 0o644);
        let key = read_storage_key_if_present(&key_path)
            .unwrap()
            .expect("a present key file must yield a key");
        assert_eq!(key, [0xab; 32]);
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }
}
