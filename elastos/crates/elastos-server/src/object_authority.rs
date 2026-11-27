//! One per-request object-authority envelope.
//!
//! The Runtime builds `ObjectAuthorityV1` from the sign-in record and drops
//! that lock before it writes the helper pipe. This slice attaches the
//! envelope on every object dispatch. The helper removes the field so the
//! request still parses, and it still reads the sign-in folder itself.
//!
//! `kept_elsewhere` is not a field. Every production
//! `ResolvedPrincipalRoot::resolve` passes the same directory as the data
//! directory and the auth directory. A subordinate Home that shares a parent
//! sign-in folder would need `record_store_is_this_home` on this envelope.

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use elastos_runtime::provider::dispatch::DispatchFence;
use elastos_runtime::provider::{Provider, ProviderError};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::auth::{self, PrincipalKind};

pub(crate) const SCHEMA: &str = "elastos.object-authority/v1";
pub(crate) const VERSION: u32 = 1;
pub(crate) const WIRE_FIELD: &str = "_runtime_object_authority";

const BAD_ROOT: &str = "object authority root is not this principal's root";
const KEY_MISMATCH: &str = "object authority key does not match its id";
const UNSUPPORTED: &str = "unsupported object authority envelope";

/// Authority for one object request. The data key is present exactly when
/// `data_key_id` is present. There is no `Clone` and no `Display`.
pub(crate) struct ObjectAuthorityV1 {
    schema: String,
    version: u32,
    principal_id: String,
    root: Option<String>,
    kind: Option<PrincipalKind>,
    data_key_id: Option<String>,
    data_key: Option<zeroize::Zeroizing<[u8; 32]>>,
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
    /// Build one envelope from the sign-in record. The activation lock taken
    /// inside `resolve` is released before this function returns. Callers
    /// must not hold it across the helper pipe.
    ///
    /// The data key stays empty in this slice. The helper still opens the
    /// sign-in folder for protected bytes. The next slice attaches the key
    /// only for operations that read or write those bytes.
    pub(crate) fn build(data_dir: &Path, principal_id: &str) -> anyhow::Result<Self> {
        let resolved = auth::ResolvedPrincipalRoot::resolve(data_dir, data_dir, principal_id)?;
        let root = resolved.localhost_root();
        let root = if root.is_empty() {
            None
        } else {
            Some(root.to_string())
        };
        let authority = Self {
            schema: SCHEMA.to_string(),
            version: VERSION,
            principal_id: principal_id.to_string(),
            root,
            kind: resolved.kind(),
            data_key_id: None,
            data_key: None,
            issued_at: auth::now_ts(),
        };
        authority.check_shape()?;
        Ok(authority)
    }

    /// Attach a freshly built envelope. The sign-in lock is not held on return.
    pub(crate) fn attach(data_dir: &Path, request: &Value) -> anyhow::Result<Value> {
        let mut request = request.clone();
        let object = request
            .as_object_mut()
            .ok_or_else(|| anyhow!("object request must be a JSON object"))?;
        let principal_id = object
            .get("principal_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let authority = Self::build(data_dir, &principal_id)?;
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

/// Attach an envelope. The binary's object probes call this. The sign-in
/// lock is not held on return.
pub fn attach_object_authority(data_dir: &Path, request: &Value) -> anyhow::Result<Value> {
    ObjectAuthorityV1::attach(data_dir, request)
}

/// Wipe the wire key in an attached request the caller still holds.
pub fn wipe_object_authority(request: &mut Value) {
    wipe_wire_key(request);
}

/// Remove a runtime envelope. This slice does not read it. A missing field
/// stays missing, so callers that have not attached one still parse.
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
/// reaches this registration carries an envelope, including a caller that
/// did not attach one itself.
pub struct AuthorityAttachingProvider {
    data_dir: PathBuf,
    inner: Arc<dyn Provider>,
}

impl AuthorityAttachingProvider {
    pub fn new(data_dir: PathBuf, inner: Arc<dyn Provider>) -> Self {
        Self { data_dir, inner }
    }

    fn prepare<'a>(&self, request: &'a Value) -> anyhow::Result<Cow<'a, Value>> {
        let op = request.get("op").and_then(Value::as_str).unwrap_or("");
        if op == "init" || op == "shutdown" || request.get(WIRE_FIELD).is_some() {
            return Ok(Cow::Borrowed(request));
        }
        Ok(Cow::Owned(ObjectAuthorityV1::attach(
            &self.data_dir,
            request,
        )?))
    }

    async fn dispatch(
        &self,
        request: &Value,
        fence: Option<DispatchFence>,
        fenced: bool,
    ) -> Result<Value, ProviderError> {
        let mut prepared = match self.prepare(request) {
            Ok(prepared) => prepared,
            Err(err) => return Ok(authority_error(&err)),
        };
        let result = if fenced {
            self.inner.send_raw_fenced(prepared.as_ref(), fence).await
        } else {
            self.inner.send_raw(prepared.as_ref()).await
        };
        if let Cow::Owned(value) = &mut prepared {
            wipe_wire_key(value);
        }
        result
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

fn json_opt_string(value: Option<&str>) -> Value {
    match value {
        Some(text) => Value::String(text.to_string()),
        None => Value::Null,
    }
}

fn json_data_key(key: Option<&zeroize::Zeroizing<[u8; 32]>>) -> Value {
    let Some(key) = key else {
        return Value::Null;
    };
    let mut encoded = auth::b64_url(key.as_slice());
    let value = Value::String(std::mem::take(&mut encoded));
    encoded.zeroize();
    value
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

    #[test]
    fn debug_never_shows_the_data_key() {
        let mut key = [7u8; 32];
        key[0] = 9;
        let encoded = auth::b64_url(&key);
        let authority = ObjectAuthorityV1 {
            schema: SCHEMA.to_string(),
            version: VERSION,
            principal_id: "device:example".to_string(),
            root: Some("localhost://Users/abc".to_string()),
            kind: None,
            data_key_id: Some(auth::principal_data_key_id(&key)),
            data_key: Some(zeroize::Zeroizing::new(key)),
            issued_at: 1,
        };
        let rendered = format!("{authority:?}");
        assert!(rendered.contains("[redacted]"), "{rendered}");
        assert!(!rendered.contains(&encoded), "{rendered}");
        assert!(!rendered.contains(&hex::encode(key)), "{rendered}");
        key.zeroize();
    }
}
