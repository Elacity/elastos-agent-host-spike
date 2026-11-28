//! One per-request object-authority envelope.
//!
//! The Runtime builds `ObjectAuthorityV1` while it still holds the sign-in
//! record, drops that lock, and hands the envelope to the object helper.
//! The helper never reads `ElastOS/System/Auth`.
//!
//! `kept_elsewhere` is not a field. `record_kept_in_another_store` is false
//! for every production `ResolvedPrincipalRoot::resolve`: each one passes the
//! same directory as the data directory and the auth directory. Only tests
//! pass a distinct auth directory. A subordinate Home that shares a parent
//! sign-in folder would need `record_store_is_this_home` on this envelope.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use elastos_runtime::auth::DEFAULT_PRINCIPAL_ROOT_CIPHER;
use elastos_runtime::provider::dispatch::DispatchFence;
use elastos_runtime::provider::{Provider, ProviderError};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::auth::{
    self, PrincipalKind, PrincipalRootObjectClass, PrincipalRootObjectDamage,
    PrincipalRootObjectEnvelopeV1, PrincipalRootObjectExpectation, PrincipalRootObjectFileClass,
    PrincipalRootObjectNotice,
};

pub(crate) const SCHEMA: &str = "elastos.object-authority/v1";
pub(crate) const VERSION: u32 = 1;
pub(crate) const WIRE_FIELD: &str = "_runtime_object_authority";
pub(crate) const RECOVERY_KEY_REFUSAL: &str =
    "object helper refuses to create the recovery archive key";

const MISSING_ENVELOPE: &str = "object request has no runtime authority envelope";
const PRINCIPAL_MISMATCH: &str = "object authority principal does not match the request";
const BAD_ROOT: &str = "object authority root is not this principal's root";
const KEY_MISMATCH: &str = "object authority key does not match its id";
const UNSUPPORTED: &str = "unsupported object authority envelope";
const KEY_NOT_32: &str = "object authority key is not a 32-byte key";
const OUTSIDE_LIBRARY: &str = "library object URI is outside the active principal root";
const OUTSIDE_RESOLVED: &str = "principal-root object URI is outside the resolved root";

/// Authority for one object request. The data key is present exactly when
/// `data_key_id` is present. There is no `Clone` and no `Display`.
pub(crate) struct ObjectAuthorityV1 {
    schema: String,
    version: u32,
    principal_id: String,
    root: Option<String>,
    kind: Option<PrincipalKind>,
    data_key_id: Option<String>,
    data_key: Option<Zeroizing<[u8; 32]>>,
    issued_at: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectAuthorityWire {
    schema: String,
    version: u32,
    principal_id: String,
    #[serde(default)]
    root: Option<String>,
    #[serde(default)]
    kind: Option<PrincipalKind>,
    #[serde(default)]
    data_key_id: Option<String>,
    #[serde(default)]
    data_key: Option<String>,
    issued_at: u64,
}

impl std::fmt::Debug for ObjectAuthorityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectAuthorityV1")
            .field("schema", &self.schema)
            .field("version", &self.version)
            .field("principal_id", &self.principal_id)
            .field("root", &self.root)
            .field("kind", &self.kind)
            .field("data_key_id", &self.data_key_id)
            .field("data_key", &self.data_key.as_ref().map(|_| "[redacted]"))
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl ObjectAuthorityV1 {
    pub(crate) fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub(crate) fn data_key_id(&self) -> Option<&str> {
        self.data_key_id.as_deref()
    }

    pub(crate) fn is_protected(&self) -> bool {
        self.data_key.is_some()
    }

    /// Localhost root for a Library operation. A remote envelope has none.
    pub(crate) fn require_local_root(&self) -> anyhow::Result<&str> {
        self.root
            .as_deref()
            .filter(|root| !root.is_empty())
            .ok_or_else(|| anyhow!(OUTSIDE_LIBRARY))
    }

    /// Build one envelope and load its data key. See `build_for`.
    pub(crate) fn build(data_dir: &Path, principal_id: &str) -> anyhow::Result<Self> {
        Self::build_for(data_dir, principal_id, true)
    }

    /// Build one envelope from the sign-in record. One audit-activation lock
    /// covers the split check, the root resolution, and the protection read.
    /// That lock is released before this function returns. Callers must not
    /// hold it across the helper pipe.
    ///
    /// `load_key` false leaves the data key unset, so a missing recovery
    /// archive key does not refuse a keyless operation.
    pub(crate) fn build_for(
        data_dir: &Path,
        principal_id: &str,
        load_key: bool,
    ) -> anyhow::Result<Self> {
        let (root, kind, loaded) = auth::with_audit_chain_activation_lock(data_dir, || {
            refuse_split_sign_in_record_locked(data_dir)?;
            #[cfg(test)]
            note_audit_lock_still_held(data_dir);
            let resolved = auth::ResolvedPrincipalRoot::resolve(data_dir, data_dir, principal_id)?;
            #[cfg(test)]
            note_audit_lock_still_held(data_dir);
            let root = resolved.localhost_root();
            let root = if root.is_empty() {
                None
            } else {
                Some(root.to_string())
            };
            let kind = resolved.kind();
            let loaded = if load_key {
                match &root {
                    Some(root) => load_data_key(data_dir, principal_id, root)?,
                    None => LoadedDataKey::none(),
                }
            } else {
                LoadedDataKey::none()
            };
            #[cfg(test)]
            note_audit_lock_still_held(data_dir);
            Ok((root, kind, loaded))
        })?;
        let authority = Self {
            schema: SCHEMA.to_string(),
            version: VERSION,
            principal_id: principal_id.to_string(),
            root,
            kind,
            data_key_id: loaded.id,
            data_key: loaded.key,
            issued_at: auth::now_ts(),
        };
        authority.check_shape()?;
        Ok(authority)
    }

    /// The helper entry. The envelope is required. This function never builds one.
    pub(crate) fn from_request(request: &mut Value) -> anyhow::Result<Self> {
        let object = request
            .as_object_mut()
            .ok_or_else(|| anyhow!("object request must be a JSON object"))?;
        let raw = object
            .remove(WIRE_FIELD)
            .ok_or_else(|| anyhow!(MISSING_ENVELOPE))?;
        let authority = Self::from_wire_value(raw)?;
        let principal = request
            .get("principal_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if authority.principal_id != principal {
            anyhow::bail!(PRINCIPAL_MISMATCH);
        }
        authority.check_shape()?;
        Ok(authority)
    }

    /// In-process Runtime entry. A present envelope is checked. A missing one
    /// is built here, because this process is the Runtime.
    pub(crate) fn from_request_or_build(
        data_dir: &Path,
        request: &mut Value,
    ) -> anyhow::Result<Self> {
        if request.get(WIRE_FIELD).is_some() {
            Self::from_request(request)
        } else {
            let principal = request
                .get("principal_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let op = request.get("op").and_then(Value::as_str).unwrap_or("");
            Self::build_for(data_dir, principal, operation_needs_data_key(op))
        }
    }

    /// Attach a freshly built envelope. The sign-in lock is not held on return.
    /// A keyless operation gets no data key, so a missing recovery archive key
    /// does not refuse it.
    pub(crate) fn attach(data_dir: &Path, request: &Value) -> anyhow::Result<Value> {
        let mut request = request.clone();
        let object = request
            .as_object_mut()
            .ok_or_else(|| anyhow!("object request must be a JSON object"))?;
        // Wipe a caller envelope before build. A failed build must not drop
        // that base64 data_key.
        if let Some(mut incoming) = object.remove(WIRE_FIELD) {
            zeroize_value(&mut incoming);
        }
        let principal_id = object
            .get("principal_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let authority = Self::build_for(data_dir, &principal_id, operation_needs_data_key(&op))?;
        object.insert(WIRE_FIELD.to_string(), authority.wire());
        Ok(request)
    }

    /// The one serialize of this envelope. Callers write it to the helper
    /// pipe and do not log it.
    pub(crate) fn wire(&self) -> Value {
        let mut map = Map::new();
        map.insert("schema".to_string(), Value::String(self.schema.clone()));
        map.insert("version".to_string(), Value::from(self.version));
        map.insert(
            "principal_id".to_string(),
            Value::String(self.principal_id.clone()),
        );
        map.insert("root".to_string(), json_opt_string(self.root.as_deref()));
        map.insert(
            "kind".to_string(),
            match self.kind {
                Some(PrincipalKind::Human) => Value::String("human".to_string()),
                Some(PrincipalKind::Agent) => Value::String("agent".to_string()),
                None => Value::Null,
            },
        );
        map.insert(
            "data_key_id".to_string(),
            json_opt_string(self.data_key_id.as_deref()),
        );
        map.insert(
            "data_key".to_string(),
            json_data_key(self.data_key.as_ref()),
        );
        map.insert("issued_at".to_string(), Value::from(self.issued_at));
        Value::Object(map)
    }

    fn from_wire_value(mut value: Value) -> anyhow::Result<Self> {
        let data_key = take_data_key(&mut value)?;
        let mut wire: ObjectAuthorityWire =
            serde_json::from_value(value).map_err(|_| anyhow!(UNSUPPORTED))?;
        if let Some(text) = wire.data_key.as_mut() {
            text.zeroize();
        }
        Ok(Self {
            schema: wire.schema,
            version: wire.version,
            principal_id: wire.principal_id,
            root: wire.root,
            kind: wire.kind,
            data_key_id: wire.data_key_id,
            data_key,
            issued_at: wire.issued_at,
        })
    }

    fn check_shape(&self) -> anyhow::Result<()> {
        if self.schema != SCHEMA || self.version != VERSION {
            anyhow::bail!(UNSUPPORTED);
        }
        match self.kind {
            Some(PrincipalKind::Human) => {
                let root = self.root.as_deref().unwrap_or("");
                if !root.starts_with("localhost://Users/") {
                    anyhow::bail!(BAD_ROOT);
                }
            }
            Some(PrincipalKind::Agent) => {
                let expected =
                    auth::principal_kind_localhost_root(&self.principal_id, PrincipalKind::Agent);
                if self.root.as_deref() != Some(expected.as_str()) {
                    anyhow::bail!(BAD_ROOT);
                }
            }
            None => match self.root.as_deref() {
                None => {}
                Some(root)
                    if self.principal_id.starts_with("device:")
                        && root.starts_with("localhost://Users/") => {}
                Some(_) => anyhow::bail!(BAD_ROOT),
            },
        }
        match (&self.data_key, &self.data_key_id) {
            (Some(key), Some(id)) if auth::principal_data_key_id(key.as_slice()) == *id => Ok(()),
            (None, None) => Ok(()),
            _ => anyhow::bail!(KEY_MISMATCH),
        }
    }
}

/// A sign-in file that is ahead of its audit checkpoint is refused here.
/// `load_auth_state` would write the checkpoint forward. This read does not.
/// `build_for` holds the audit lock across this read and the two that follow.
fn refuse_split_sign_in_record_locked(data_dir: &Path) -> anyhow::Result<()> {
    let Some(state) = auth::load_auth_state_unverified(data_dir)? else {
        return Ok(());
    };
    let activation = auth::load_audit_chain_activation_unlocked(data_dir)?;
    match (state.audit_chain_state.as_ref(), activation.as_ref()) {
        (Some(chain_state), Some(activation)) => {
            if chain_state.activated_at != activation.activated_at {
                anyhow::bail!("audit chain state does not match its activation record");
            }
            let Some(checkpoint) = auth::audit_chain_checkpoint(&state)? else {
                anyhow::bail!("audit chain state does not match its activation record");
            };
            if auth::validate_checkpoint_progress(&activation.checkpoint, &checkpoint)? {
                anyhow::bail!("audit chain state does not match its activation record");
            }
            Ok(())
        }
        (Some(_), None) => {
            anyhow::bail!("audit chain state does not match its activation record");
        }
        (None, Some(_)) => {
            anyhow::bail!("audit chain state is required after activation");
        }
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
std::thread_local! {
    static AUDIT_LOCK_HITS: std::cell::RefCell<
        Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    > = const { std::cell::RefCell::new(None) };
}

/// Armed by the concurrency row. A second thread tries the audit lock while
/// this thread is between the Auth reads. Deleting the lock in `build_for`
/// lets that try succeed, and the row fails.
#[cfg(test)]
fn note_audit_lock_still_held(data_dir: &Path) {
    let hits = AUDIT_LOCK_HITS.with(|slot| slot.borrow().clone());
    let Some(hits) = hits else {
        return;
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let path = data_dir.to_path_buf();
    let checker = std::thread::spawn(move || {
        let acquired = auth::try_audit_activation_lock_for_test(&path);
        tx.send(acquired).expect("the lock check sends");
    });
    let acquired = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("the lock check returns");
    checker.join().expect("the lock check joins");
    assert!(
        !acquired,
        "build_for released the audit lock between Auth reads"
    );
    hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn arm_audit_lock_proof(hits: std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    AUDIT_LOCK_HITS.with(|slot| *slot.borrow_mut() = Some(hits));
}

#[cfg(test)]
fn disarm_audit_lock_proof() {
    AUDIT_LOCK_HITS.with(|slot| *slot.borrow_mut() = None);
}

struct LoadedDataKey {
    id: Option<String>,
    key: Option<Zeroizing<[u8; 32]>>,
}

impl LoadedDataKey {
    fn none() -> Self {
        Self {
            id: None,
            key: None,
        }
    }
}

fn load_data_key(data_dir: &Path, principal_id: &str, root: &str) -> anyhow::Result<LoadedDataKey> {
    let Some(protection) = auth::load_principal_root_protection(data_dir, principal_id, root)?
    else {
        return Ok(LoadedDataKey::none());
    };
    let key_path = auth::recovery_archive_key_path(data_dir)?;
    if !key_path.is_file() {
        anyhow::bail!(RECOVERY_KEY_REFUSAL);
    }
    let mut raw = auth::principal_root_data_key_from_protection(data_dir, &protection)?;
    let id = auth::principal_data_key_id(&raw);
    if id != protection.data_key_id {
        raw.zeroize();
        anyhow::bail!(KEY_MISMATCH);
    }
    let key = Zeroizing::new(raw);
    raw.zeroize();
    Ok(LoadedDataKey {
        id: Some(protection.data_key_id),
        key: Some(key),
    })
}

fn decode_data_key(text: &str) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut decoded = auth::b64_url_decode(text).map_err(|_| anyhow!(KEY_NOT_32))?;
    if decoded.len() != 32 {
        decoded.zeroize();
        anyhow::bail!(KEY_NOT_32);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(Zeroizing::new(key))
}

fn json_opt_string(value: Option<&str>) -> Value {
    match value {
        Some(text) => Value::String(text.to_string()),
        None => Value::Null,
    }
}

fn json_data_key(key: Option<&Zeroizing<[u8; 32]>>) -> Value {
    let Some(key) = key else {
        return Value::Null;
    };
    Value::String(auth::b64_url(key.as_slice()))
}

pub(crate) fn operation_needs_data_key(op: &str) -> bool {
    !matches!(
        op,
        "roots"
            | "list_runtime_custody"
            | "import_runtime_custody"
            | "buy"
            | "open_viewer"
            | "read_viewer"
            | "close_viewer"
    )
}

fn take_data_key(value: &mut Value) -> anyhow::Result<Option<Zeroizing<[u8; 32]>>> {
    let Some(object) = value.as_object_mut() else {
        anyhow::bail!(UNSUPPORTED);
    };
    let Some(raw) = object.remove("data_key") else {
        return Ok(None);
    };
    let decoded = match raw {
        Value::Null => None,
        Value::String(mut text) => {
            let decoded = if text.is_empty() {
                None
            } else {
                match decode_data_key(&text) {
                    Ok(key) => Some(key),
                    Err(err) => {
                        text.zeroize();
                        return Err(err);
                    }
                }
            };
            text.zeroize();
            decoded
        }
        mut other => {
            zeroize_value(&mut other);
            anyhow::bail!(KEY_NOT_32);
        }
    };
    if let Some(object) = value.as_object_mut() {
        object.insert("data_key".to_string(), Value::Null);
    }
    Ok(decoded)
}

fn bound_root<'a>(
    authority: &'a ObjectAuthorityV1,
    data_dir: &Path,
    uri: &str,
    path: &Path,
) -> anyhow::Result<&'a str> {
    let root = authority.require_local_root()?;
    if !auth::object_uri_is_under_root(root, uri) {
        anyhow::bail!(OUTSIDE_RESOLVED);
    }
    auth::validate_principal_root_object_path(data_dir, uri, path)?;
    auth::ensure_no_symlink_components(data_dir, path)?;
    Ok(root)
}

pub(crate) fn read_principal_root_object_with_authority(
    authority: &ObjectAuthorityV1,
    path: &Path,
    uri: &str,
    data_dir: &Path,
) -> anyhow::Result<Vec<u8>> {
    let root = bound_root(authority, data_dir, uri, path)?;
    let _guard = auth::principal_root_object_mutation_lock(data_dir)
        .lock()
        .map_err(|_| anyhow!("principal-root object mutation lock poisoned"))?;
    #[cfg(test)]
    auth::principal_object_io::record_read(data_dir, path);
    if authority.data_key.is_none() {
        let (mut file, _) = auth::open_principal_root_object_file(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .with_context(|| format!("failed to read {path:?}"))?;
        return Ok(bytes);
    }
    read_protected(authority, data_dir, root, uri, path)
}

fn read_protected(
    authority: &ObjectAuthorityV1,
    data_dir: &Path,
    root: &str,
    uri: &str,
    path: &Path,
) -> anyhow::Result<Vec<u8>> {
    let (mut file, len) = auth::open_principal_root_object_file(path)?;
    let data_key_id = authority
        .data_key_id
        .as_deref()
        .ok_or_else(|| anyhow!(KEY_MISMATCH))?;
    let expected = PrincipalRootObjectExpectation {
        principal_id: authority.principal_id(),
        localhost_root: root,
        object_uri: uri,
        data_key_id: Some(data_key_id),
    };
    let mut whole_read_budget = auth::MAX_MIGRATION_OBJECT_BYTES;
    let probe = auth::classify_principal_root_object_file(
        &mut file,
        len,
        &expected,
        &mut whole_read_budget,
    )
    .with_context(|| format!("failed to read {path:?}"))?;
    let damage = match probe.class {
        PrincipalRootObjectFileClass::Plaintext
        | PrincipalRootObjectFileClass::UnconfirmedPlaintext => {
            anyhow::bail!(
                "{}: {}",
                auth::PROTECTED_PRINCIPAL_ROOT_OBJECT_NOT_ENCRYPTED,
                auth::printable_text(uri)
            );
        }
        PrincipalRootObjectFileClass::Envelope => PrincipalRootObjectDamage::FailedCheck,
        PrincipalRootObjectFileClass::Damaged(damage) => damage,
    };
    let damaged = |damage| {
        auth::principal_root_object_damaged_error(&PrincipalRootObjectNotice::new(
            data_dir, root, uri, damage,
        ))
    };
    if auth::principal_root_object_label_never_opens(&damage) {
        return Err(damaged(damage));
    }
    let data_key = authority
        .data_key
        .as_ref()
        .ok_or_else(|| anyhow!(KEY_MISMATCH))?;
    let bytes = auth::read_principal_root_object_rest(&mut file, probe.prefix)
        .with_context(|| format!("failed to read {path:?}"))?;
    auth::decrypt_principal_root_object_envelope_bytes(data_key, &expected, &bytes)
        .map_err(|_| damaged(damage))
}

pub(crate) fn principal_root_object_content_bound_with_authority(
    authority: &ObjectAuthorityV1,
    path: &Path,
    uri: &str,
    data_dir: &Path,
) -> anyhow::Result<u64> {
    let root = bound_root(authority, data_dir, uri, path)?;
    let (mut file, len) = auth::open_principal_root_object_file(path)?;
    let expected = PrincipalRootObjectExpectation {
        principal_id: authority.principal_id(),
        localhost_root: root,
        object_uri: uri,
        data_key_id: authority.data_key_id(),
    };
    let mut no_whole_reads = 0;
    let probe =
        auth::classify_principal_root_object_file(&mut file, len, &expected, &mut no_whole_reads)
            .with_context(|| format!("failed to read {path:?}"))?;
    Ok(match probe.class {
        PrincipalRootObjectFileClass::Envelope => {
            auth::envelope_bound::envelope_content_bound(len, &probe.prefix)
        }
        _ => len,
    })
}

pub(crate) fn write_principal_root_object_with_authority(
    authority: &ObjectAuthorityV1,
    path: &Path,
    uri: &str,
    data_dir: &Path,
    plaintext: &[u8],
    create_only: bool,
) -> anyhow::Result<()> {
    let root = bound_root(authority, data_dir, uri, path)?;
    let _guard = auth::principal_root_object_mutation_lock(data_dir)
        .lock()
        .map_err(|_| anyhow!("principal-root object mutation lock poisoned"))?;
    #[cfg(test)]
    auth::principal_object_io::record_write(data_dir, path);
    let bytes = sealed_bytes(authority, root, uri, plaintext)?;
    if create_only {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        auth::write_owner_only_new_file(path, &bytes)?;
        crate::auth_state_files::sync_parent_directory(path)?;
        return Ok(());
    }
    auth::atomic_write(path, &bytes)
}

pub(crate) fn create_principal_root_object_with_authority(
    authority: &ObjectAuthorityV1,
    path: &Path,
    uri: &str,
    data_dir: &Path,
    plaintext: &[u8],
) -> anyhow::Result<()> {
    write_principal_root_object_with_authority(authority, path, uri, data_dir, plaintext, true)
}

fn sealed_bytes(
    authority: &ObjectAuthorityV1,
    root: &str,
    uri: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let Some(data_key) = authority.data_key.as_ref() else {
        return Ok(plaintext.to_vec());
    };
    let data_key_id = authority
        .data_key_id
        .as_deref()
        .ok_or_else(|| anyhow!(KEY_MISMATCH))?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut envelope = PrincipalRootObjectEnvelopeV1 {
        schema: auth::PRINCIPAL_ROOT_OBJECT_SCHEMA.to_string(),
        principal_id: authority.principal_id().to_string(),
        localhost_root: root.to_string(),
        data_key_id: data_key_id.to_string(),
        object_uri: uri.to_string(),
        cipher: DEFAULT_PRINCIPAL_ROOT_CIPHER.to_string(),
        nonce: auth::b64_url(&nonce),
        ciphertext: String::new(),
    };
    envelope.ciphertext = auth::encrypt_aes256_gcm_bytes_with_aad(
        data_key.as_slice(),
        &nonce,
        plaintext,
        auth::principal_root_object_aad(&envelope).as_bytes(),
    )?;
    nonce.zeroize();
    Ok(serde_json::to_vec_pretty(&envelope)?)
}

pub(crate) fn protect_legacy_plaintext_with_authority(
    authority: &ObjectAuthorityV1,
    path: &Path,
    uri: &str,
    data_dir: &Path,
) -> anyhow::Result<Vec<u8>> {
    let root = bound_root(authority, data_dir, uri, path)?;
    let too_large = || {
        anyhow!(
            "{}: {} is not encrypted and is larger \
             than 16 MiB, so Home will not encrypt it in place. Move it out of {}, then upload \
             it again in Library.",
            auth::PROTECTED_PRINCIPAL_ROOT_OBJECT_NOT_ENCRYPTED,
            auth::principal_root_home_relative_path(root, uri),
            auth::principal_root_disk_folder(data_dir, uri),
        )
    };
    let (file, len) = auth::open_principal_root_object_file(path)?;
    if len > auth::MAX_MIGRATION_OBJECT_BYTES {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(auth::MAX_MIGRATION_OBJECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read legacy plaintext library object {path:?}"))?;
    if bytes.len() as u64 > auth::MAX_MIGRATION_OBJECT_BYTES {
        return Err(too_large());
    }
    let data_key_id = authority
        .data_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("principal-root protection is missing"))?;
    let expected = PrincipalRootObjectExpectation {
        principal_id: authority.principal_id(),
        localhost_root: root,
        object_uri: uri,
        data_key_id: Some(data_key_id),
    };
    match auth::classify_principal_root_object_bytes(&bytes, &expected) {
        PrincipalRootObjectClass::Plaintext => {}
        PrincipalRootObjectClass::Envelope => {
            return Err(auth::principal_root_object_changed_error(root, uri));
        }
        PrincipalRootObjectClass::Damaged(damage) => {
            return Err(auth::principal_root_object_damaged_error(
                &PrincipalRootObjectNotice::new(data_dir, root, uri, damage),
            ));
        }
    }
    write_principal_root_object_with_authority(authority, path, uri, data_dir, &bytes, false)?;
    Ok(bytes)
}

/// Attach an envelope. The binary's object probes call this. The sign-in
/// lock is not held on return.
pub fn attach_object_authority(data_dir: &Path, request: &Value) -> anyhow::Result<Value> {
    ObjectAuthorityV1::attach(data_dir, request)
}

/// Wipe the wire key in an attached request the caller still holds.
pub fn wipe_object_authority(request: &mut Value) {
    wipe_wire_key(request);
}

/// Remove a caller envelope from a lifecycle request. Init and shutdown
/// carry no principal, so the Runtime does not insert its own envelope.
pub(crate) fn accept_envelope(request: &mut Value) {
    let Some(object) = request.as_object_mut() else {
        return;
    };
    let Some(mut removed) = object.remove(WIRE_FIELD) else {
        return;
    };
    zeroize_value(&mut removed);
}

/// Owns one attached request and wipes the wire key when dropped.
/// `AuthorityAttachingProvider::dispatch` holds this across the helper
/// await, so cancellation wipes the key too.
pub(crate) struct AttachedRequest {
    value: Value,
}

impl AttachedRequest {
    pub(crate) fn new(data_dir: &Path, request: &Value) -> anyhow::Result<Self> {
        Ok(Self {
            value: ObjectAuthorityV1::attach(data_dir, request)?,
        })
    }

    pub(crate) fn value(&self) -> &Value {
        &self.value
    }
}

impl Drop for AttachedRequest {
    fn drop(&mut self) {
        wipe_wire_key(&mut self.value);
    }
}

pub(crate) fn wipe_wire_key(request: &mut Value) {
    let Some(authority) = request.get_mut(WIRE_FIELD) else {
        return;
    };
    zeroize_value(authority);
}

/// The confined object provider registered by the server. A `send_raw` that
/// reaches this registration carries the Runtime's envelope. Any envelope
/// the caller supplied is removed and is not forwarded.
pub struct AuthorityAttachingProvider {
    data_dir: PathBuf,
    inner: Arc<dyn Provider>,
}

impl AuthorityAttachingProvider {
    pub fn new(data_dir: PathBuf, inner: Arc<dyn Provider>) -> Self {
        Self { data_dir, inner }
    }

    async fn dispatch(
        &self,
        request: &Value,
        fence: Option<DispatchFence>,
        fenced: bool,
    ) -> Result<Value, ProviderError> {
        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        // Lifecycle ops have no principal. Strip a caller envelope and do
        // not insert one. The key is wiped before the await.
        if op == "init" || op == "shutdown" {
            let mut stripped = request.clone();
            accept_envelope(&mut stripped);
            return if fenced {
                self.inner.send_raw_fenced(&stripped, fence).await
            } else {
                self.inner.send_raw(&stripped).await
            };
        }
        // Hold the attached value across the await. Drop wipes the wire key
        // when the helper returns and when this future is cancelled.
        let attached = match AttachedRequest::new(&self.data_dir, request) {
            Ok(attached) => attached,
            Err(err) => return Ok(authority_error(&err)),
        };
        if fenced {
            self.inner.send_raw_fenced(attached.value(), fence).await
        } else {
            self.inner.send_raw(attached.value()).await
        }
    }
}

#[async_trait]
impl Provider for AuthorityAttachingProvider {
    async fn handle(
        &self,
        request: elastos_runtime::provider::ResourceRequest,
    ) -> Result<elastos_runtime::provider::ResourceResponse, ProviderError> {
        self.inner.handle(request).await
    }

    fn schemes(&self) -> Vec<&'static str> {
        self.inner.schemes()
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }

    async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
        self.dispatch(request, None, false).await
    }

    async fn send_raw_fenced(
        &self,
        request: &Value,
        fence: Option<DispatchFence>,
    ) -> Result<Value, ProviderError> {
        self.dispatch(request, fence, true).await
    }

    async fn shutdown(&self) -> Result<(), ProviderError> {
        self.inner.shutdown().await
    }
}

fn authority_error(err: &anyhow::Error) -> Value {
    serde_json::json!({
        "status": "error",
        "code": "library_error",
        "message": err.to_string(),
    })
}

fn zeroize_value(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                zeroize_value(item);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                zeroize_value(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn device_request(key: &[u8; 32], extra: Option<(&str, Value)>) -> (Value, String) {
        let id = auth::principal_data_key_id(key);
        let encoded = auth::b64_url(key);
        let mut envelope = json!({
            "schema": SCHEMA,
            "version": VERSION,
            "principal_id": "device:example",
            "root": "localhost://Users/abc",
            "kind": null,
            "data_key_id": id,
            "data_key": encoded,
            "issued_at": 1
        });
        if let Some((name, value)) = extra {
            envelope
                .as_object_mut()
                .expect("envelope object")
                .insert(name.to_string(), value);
        }
        let request = json!({
            "op": "list",
            "principal_id": "device:example",
            WIRE_FIELD: envelope,
        });
        (request, encoded)
    }

    #[test]
    fn debug_never_shows_the_data_key() {
        let mut key = [7u8; 32];
        key[0] = 9;
        let (mut request, encoded) = device_request(&key, None);
        let authority = ObjectAuthorityV1::from_request(&mut request).expect("envelope");
        let rendered = format!("{authority:?}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains(&encoded), "{rendered}");
        assert!(!rendered.contains(&hex::encode(key)), "{rendered}");
        assert!(request.get(WIRE_FIELD).is_none());
        key.zeroize();
    }

    #[test]
    fn from_request_refuses_a_principal_mismatch_and_an_unknown_field() {
        let key = [3u8; 32];
        let (mut request, _) = device_request(&key, None);
        request["principal_id"] = json!("device:other");
        let error = ObjectAuthorityV1::from_request(&mut request).unwrap_err();
        assert!(error.to_string().contains(PRINCIPAL_MISMATCH), "{error}");
        assert!(request.get(WIRE_FIELD).is_none());

        let (mut request, _) = device_request(&key, Some(("extra", json!(true))));
        let error = ObjectAuthorityV1::from_request(&mut request).unwrap_err();
        assert!(error.to_string().contains(UNSUPPORTED), "{error}");
    }

    #[test]
    fn from_request_refuses_a_human_without_a_root_and_a_key_that_does_not_match() {
        let mut request = json!({
            "op": "list",
            "principal_id": "person:local:ada",
            WIRE_FIELD: {
                "schema": SCHEMA,
                "version": VERSION,
                "principal_id": "person:local:ada",
                "root": null,
                "kind": "human",
                "data_key_id": null,
                "data_key": null,
                "issued_at": 1
            }
        });
        let error = ObjectAuthorityV1::from_request(&mut request).unwrap_err();
        assert!(error.to_string().contains(BAD_ROOT), "{error}");

        let mut request = json!({
            "op": "read",
            "principal_id": "device:example",
            WIRE_FIELD: {
                "schema": SCHEMA,
                "version": VERSION,
                "principal_id": "device:example",
                "root": "localhost://Users/abc",
                "kind": null,
                "data_key_id": "pdek:not-this-key",
                "data_key": auth::b64_url(&[4u8; 32]),
                "issued_at": 1
            }
        });
        let error = ObjectAuthorityV1::from_request(&mut request).unwrap_err();
        assert!(error.to_string().contains(KEY_MISMATCH), "{error}");
        assert!(!format!("{error}").contains(&auth::b64_url(&[4u8; 32])));
    }

    #[test]
    fn a_missing_envelope_is_refused_without_building_one() {
        let mut request = json!({"op": "list", "principal_id": "device:example"});
        let error = ObjectAuthorityV1::from_request(&mut request).unwrap_err();
        assert!(error.to_string().contains(MISSING_ENVELOPE), "{error}");
    }

    struct RecordingProvider {
        seen: std::sync::Arc<std::sync::Mutex<Option<Value>>>,
    }

    #[async_trait::async_trait]
    impl Provider for RecordingProvider {
        async fn handle(
            &self,
            _request: elastos_runtime::provider::ResourceRequest,
        ) -> Result<elastos_runtime::provider::ResourceResponse, ProviderError> {
            Err(ProviderError::Provider(
                "resource requests are not used in this test".to_string(),
            ))
        }

        fn schemes(&self) -> Vec<&'static str> {
            Vec::new()
        }

        fn name(&self) -> &'static str {
            "recording-object"
        }

        async fn send_raw(&self, request: &Value) -> Result<Value, ProviderError> {
            *self.seen.lock().expect("lock") = Some(request.clone());
            Ok(serde_json::json!({ "status": "ok" }))
        }
    }

    /// The inner provider must see the Runtime envelope. Deleting the insert
    /// in `ObjectAuthorityV1::attach`, or forwarding a caller-supplied
    /// envelope, leaves this red.
    #[tokio::test]
    async fn runtime_envelope_replaces_a_caller_supplied_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let person = auth::upsert_principal_for_binding(
            dir.path(),
            elastos_auth::ProofBinding::evm_account(20, &format!("0x{}", "ab".repeat(20)), 1),
            1,
        )
        .expect("principal");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let provider = AuthorityAttachingProvider::new(
            dir.path().to_path_buf(),
            Arc::new(RecordingProvider {
                seen: std::sync::Arc::clone(&seen),
            }),
        );
        let request = serde_json::json!({
            "op": "list",
            "principal_id": person.principal_id,
            WIRE_FIELD: {
                "schema": "forged",
                "marker": "CALLER-SUPPLIED-ENVELOPE",
                "data_key": "caller-supplied-key"
            }
        });
        let reply = provider.send_raw(&request).await.expect("dispatch");
        assert_eq!(reply["status"], "ok", "{reply}");
        let recorded = seen
            .lock()
            .expect("lock")
            .clone()
            .expect("the inner provider saw no request");
        let envelope = recorded
            .get(WIRE_FIELD)
            .expect("the runtime envelope was not inserted");
        assert_eq!(envelope["schema"].as_str(), Some(SCHEMA));
        assert_eq!(envelope["version"].as_u64(), Some(u64::from(VERSION)));
        assert_eq!(
            envelope["principal_id"].as_str(),
            Some(person.principal_id.as_str())
        );
        let rendered = recorded.to_string();
        assert!(!rendered.contains("CALLER-SUPPLIED-ENVELOPE"), "{rendered}");
        assert!(!rendered.contains("caller-supplied-key"), "{rendered}");
        assert!(!rendered.contains("forged"), "{rendered}");
    }

    /// Concurrent audit saves beside `build`. The first build also checks that
    /// the audit lock stays held across the split check, the root resolution,
    /// and the protection read. Deleting that one lock makes the check acquire
    /// it, so this row fails before the race has to lose.
    #[test]
    fn build_holds_one_audit_lock_beside_appended_audit_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let principal = "person:local:ada";
        auth::store_test_human_principal(dir.path(), principal);
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        arm_audit_lock_proof(std::sync::Arc::clone(&hits));
        struct ClearProof;
        impl Drop for ClearProof {
            fn drop(&mut self) {
                disarm_audit_lock_proof();
            }
        }
        let _clear = ClearProof;
        ObjectAuthorityV1::build(dir.path(), principal).expect("locked build");
        disarm_audit_lock_proof();
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "the three Auth reads did not all run while the audit lock was held"
        );

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let saver = std::thread::spawn({
            let data = dir.path().to_path_buf();
            let stop = std::sync::Arc::clone(&stop);
            move || {
                let mut index = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    auth::append_audit_event(
                        &data,
                        elastos_runtime::auth::RuntimeAuditEventV1 {
                            schema: elastos_runtime::auth::RuntimeAuditEventV1::SCHEMA.to_string(),
                            event_id: format!("audit:build-race:{index}"),
                            event_type: "test.audit".to_string(),
                            principal_id: Some(principal.to_string()),
                            proof_binding_id: None,
                            session_id: Some("session:test".to_string()),
                            challenge_id: None,
                            capsule_id: Some("system".to_string()),
                            result: "allowed".to_string(),
                            reason: format!("build race {index}"),
                            occurred_at: index + 1,
                            signer_did: None,
                            signature: None,
                        },
                    )
                    .expect("audit save");
                    index += 1;
                }
                index
            }
        });
        let mut builds = 0u32;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while builds < 25 && std::time::Instant::now() < deadline {
            ObjectAuthorityV1::build(dir.path(), principal).expect("build beside an audit save");
            builds += 1;
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let saves = saver.join().expect("saver");
        assert!(
            builds >= 25,
            "{builds} builds finished beside {saves} audit saves"
        );
        assert!(saves >= 1, "{saves} audit saves ran beside the builds");
    }

    /// The caller envelope is wiped before `build`. Moving the wipe below
    /// `Self::build` leaves this red: a failed build would drop the key.
    #[test]
    fn attach_wipes_a_caller_envelope_before_build() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/object_authority.rs");
        let text = std::fs::read_to_string(&path).expect("object authority source");
        let marker = "pub(crate) fn attach(";
        let start = text.find(marker).expect("attach");
        let body = &text[start..];
        let end = body
            .find("\n    /// The one serialize")
            .expect("end of attach");
        let body = &body[..end];
        let wipe = body.find("zeroize_value(").expect("wipe");
        let build = body.find("Self::build").expect("build");
        assert!(
            wipe < build,
            "attach drops a caller data_key when build fails"
        );
    }
}
