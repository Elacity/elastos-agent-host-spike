//! Prepared object authority contract. Production retains its existing authority.
//!
//! Runtime owns principal/root resolution and supplies the envelope over its
//! trusted channel. Parsing checks that assertion; it does not authenticate a
//! caller-supplied envelope. This module performs no storage or key acquisition.

use anyhow::{anyhow, bail};
use serde::Deserialize;
use serde_json::Value;

const SCHEMA: &str = "elastos.object-authority/v1";
const VERSION: u32 = 1;
const WIRE_FIELD: &str = "_runtime_object_authority";
const MISSING_ENVELOPE: &str = "object request requires a runtime authority envelope";
const PRINCIPAL_MISMATCH: &str = "object authority principal does not match the request";
const UNSUPPORTED: &str = "unsupported object authority envelope";
const BAD_ROOT: &str = "object authority requires a stored principal root";
const METADATA_ONLY: &str = "metadata authority cannot access object content";
const KEY_REQUIRED: &str = "protected content requires its matching data key";

/// Immutable, validated principal/root binding. Only the wire validator constructs it.
pub struct ObjectAuthorityV1 {
    principal_id: String,
    root: String,
    access: Access,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObjectAuthorityWire {
    schema: String,
    version: u32,
    principal_id: String,
    root: String,
    access: Access,
}

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Access {
    Metadata {},
    StoredUnprotected {},
    Protected { data_key_id: String },
}

/// A content capability borrows its immutable context and any supplied key.
/// Private fields keep metadata access from constructing a content capability.
pub struct ContentAccess<'a> {
    authority: &'a ObjectAuthorityV1,
    protection: ContentProtection<'a>,
}

/// Storage must handle the explicit protection choice before writing content.
/// A protected choice always carries a key; plaintext requires stored authority.
pub enum ContentProtection<'a> {
    StoredUnprotected,
    Protected { data_key: &'a [u8; 32] },
}

impl ObjectAuthorityV1 {
    /// Validate a trusted Runtime assertion before the caller enters storage.
    /// Unknown envelope and access fields refuse, including legacy key fields.
    pub fn from_request(request: &Value) -> anyhow::Result<Self> {
        let raw = request
            .get(WIRE_FIELD)
            .ok_or_else(|| anyhow!(MISSING_ENVELOPE))?;
        let wire: ObjectAuthorityWire =
            serde_json::from_value(raw.clone()).map_err(|_| anyhow!(UNSUPPORTED))?;
        if wire.schema != SCHEMA || wire.version != VERSION {
            bail!(UNSUPPORTED);
        }
        if wire.principal_id.is_empty()
            || request.get("principal_id").and_then(Value::as_str)
                != Some(wire.principal_id.as_str())
        {
            bail!(PRINCIPAL_MISMATCH);
        }
        let directory = wire
            .root
            .strip_prefix("localhost://Users/")
            .or_else(|| wire.root.strip_prefix("localhost://UsersAI/"))
            .ok_or_else(|| anyhow!(BAD_ROOT))?;
        if directory.is_empty()
            || !directory
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!(BAD_ROOT);
        }
        if let Access::Protected { data_key_id } = &wire.access {
            let digest = data_key_id
                .strip_prefix("pdek:")
                .ok_or_else(|| anyhow!(KEY_REQUIRED))?;
            if digest.len() != 32 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!(KEY_REQUIRED);
            }
        }
        Ok(Self {
            principal_id: wire.principal_id,
            root: wire.root,
            access: wire.access,
        })
    }

    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    /// Admit content using an explicitly supplied key, without acquiring one.
    /// Metadata always refuses. Only stored-unprotected authority admits plaintext.
    pub fn content_access<'a>(
        &'a self,
        data_key: Option<&'a [u8; 32]>,
    ) -> anyhow::Result<ContentAccess<'a>> {
        let protection = match &self.access {
            Access::Metadata {} => bail!(METADATA_ONLY),
            Access::StoredUnprotected {} => {
                if data_key.is_some() {
                    bail!("stored-unprotected authority received a protected content key");
                }
                ContentProtection::StoredUnprotected
            }
            Access::Protected { data_key_id } => {
                let data_key = data_key.ok_or_else(|| anyhow!(KEY_REQUIRED))?;
                if crate::auth::principal_data_key_id(data_key) != *data_key_id {
                    bail!(KEY_REQUIRED);
                }
                ContentProtection::Protected { data_key }
            }
        };
        Ok(ContentAccess {
            authority: self,
            protection,
        })
    }
}

impl ContentAccess<'_> {
    pub fn authority(&self) -> &ObjectAuthorityV1 {
        self.authority
    }

    pub fn protection(&self) -> &ContentProtection<'_> {
        &self.protection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;

    fn request(access: Value) -> Value {
        json!({
            "principal_id": "person:local:ada",
            WIRE_FIELD: {
                "schema": SCHEMA,
                "version": VERSION,
                "principal_id": "person:local:ada",
                "root": "localhost://Users/stored-root",
                "access": access
            }
        })
    }

    fn unprotected_request() -> Value {
        request(json!({"mode": "stored_unprotected"}))
    }

    // This storage stand-in is reached only with a content capability. It
    // records both entry and the selected protection, rather than error wording.
    fn write_content(access: ContentAccess<'_>, storage: &Cell<usize>) -> bool {
        storage.set(storage.get() + 1);
        matches!(access.protection(), ContentProtection::StoredUnprotected)
    }

    fn attempt_write(
        request: &Value,
        key: Option<&[u8; 32]>,
        storage: &Cell<usize>,
    ) -> anyhow::Result<bool> {
        let authority = ObjectAuthorityV1::from_request(request)?;
        Ok(write_content(authority.content_access(key)?, storage))
    }

    fn assert_refused_before_storage(request: &Value, key: Option<&[u8; 32]>) {
        let storage = Cell::new(0);
        let result = attempt_write(request, key, &storage);
        assert_eq!(storage.get(), 0, "refused request entered storage");
        assert!(result.is_err(), "request unexpectedly admitted");
    }

    #[test]
    fn row_a_missing_envelope_refuses_before_storage() {
        let mut request = unprotected_request();
        request.as_object_mut().unwrap().remove(WIRE_FIELD);
        assert_refused_before_storage(&request, None);
    }

    #[test]
    fn row_a_wrong_principal_refuses_before_storage() {
        let mut request = unprotected_request();
        request["principal_id"] = json!("person:local:other");
        assert_refused_before_storage(&request, None);
    }

    #[test]
    fn row_a_unsupported_schema_refuses_before_storage() {
        let mut request = unprotected_request();
        request[WIRE_FIELD]["schema"] = json!("elastos.object-authority/v2");
        assert_refused_before_storage(&request, None);
    }

    #[test]
    fn row_a_unknown_fields_refuse_before_storage() {
        let mut request = unprotected_request();
        request[WIRE_FIELD]["extra"] = json!(true);
        assert_refused_before_storage(&request, None);
    }

    #[test]
    fn row_b_metadata_cannot_invoke_content_write() {
        let request = request(json!({"mode": "metadata"}));
        let authority = ObjectAuthorityV1::from_request(&request).unwrap();
        assert_eq!(authority.principal_id(), "person:local:ada");
        assert_eq!(authority.root(), "localhost://Users/stored-root");
        assert_refused_before_storage(&request, None);
        assert_refused_before_storage(&request, Some(&[7; 32]));
    }

    #[test]
    fn row_b_missing_key_cannot_select_plaintext() {
        let key = [7; 32];
        let request = request(json!({
            "mode": "protected", "data_key_id": crate::auth::principal_data_key_id(&key)
        }));
        assert_refused_before_storage(&request, None);
        assert_refused_before_storage(&request, Some(&[8; 32]));
        let storage = Cell::new(0);
        assert!(!attempt_write(&request, Some(&key), &storage).unwrap());
        assert_eq!(storage.get(), 1);
        let authority = ObjectAuthorityV1::from_request(&request).unwrap();
        let access = authority.content_access(Some(&key)).unwrap();
        assert_eq!(access.authority().root(), authority.root());
        match access.protection() {
            ContentProtection::Protected { data_key } => assert_eq!(*data_key, &key),
            ContentProtection::StoredUnprotected => panic!("protected access became plaintext"),
        }
    }

    #[test]
    fn only_explicit_stored_unprotected_access_admits_plaintext() {
        let request = unprotected_request();
        let storage = Cell::new(0);
        assert!(attempt_write(&request, None, &storage).unwrap());
        assert_eq!(storage.get(), 1);
        assert_refused_before_storage(&request, Some(&[7; 32]));
        let mut missing_access = request;
        missing_access[WIRE_FIELD]
            .as_object_mut()
            .unwrap()
            .remove("access");
        assert_refused_before_storage(&missing_access, None);
    }

    #[test]
    fn malformed_authority_and_nested_unknown_fields_refuse() {
        let mut request = unprotected_request();
        for value in [Value::Null, json!("envelope"), json!({})] {
            request[WIRE_FIELD] = value;
            assert_refused_before_storage(&request, None);
        }
        let mut request = unprotected_request();
        request[WIRE_FIELD]["version"] = json!(2);
        assert_refused_before_storage(&request, None);
        for access in [
            json!({"mode": "metadata", "extra": true}),
            json!({"mode": "stored_unprotected", "data_key": null}),
            json!({"mode": "protected"}),
            json!({"mode": "protected", "data_key_id": "invalid"}),
            json!({"mode": "protected", "data_key_id": "pdek:bad"}),
            json!({"mode": "future"}),
        ] {
            assert_refused_before_storage(&super::tests::request(access), None);
        }
    }

    #[test]
    fn root_is_stored_unchanged_and_invalid_roots_refuse() {
        let mut request = unprotected_request();
        request[WIRE_FIELD]["root"] = json!("localhost://UsersAI/stored-agent");
        let authority = ObjectAuthorityV1::from_request(&request).unwrap();
        assert_eq!(authority.root(), "localhost://UsersAI/stored-agent");
        for root in [
            "",
            "localhost://Users/",
            "localhost://Users/../Auth",
            "localhost://Users/a/b",
            "localhost://Users/a%2fb",
            "localhost://Users/a\\b",
            "localhost://ElastOS/System/Auth",
        ] {
            request[WIRE_FIELD]["root"] = json!(root);
            assert_refused_before_storage(&request, None);
        }
    }
}
