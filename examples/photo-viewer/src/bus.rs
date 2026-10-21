//! The two Bus calls this guest makes, behind a trait so host tests can fake
//! the Runtime.
//!
//! On wasm32 the trait is implemented over the `elastos:bus@v1` imports. The
//! request and response shapes follow the Runtime bridge:
//! `providers.invoke` returns the provider result as JSON bytes
//! (`elastos-compute/src/providers/component.rs:396-414`), and a
//! `read` answers `{"content": [bytes], "size": n}` and honors an
//! offset/length window on both paths: Runtime-handled principal roots
//! (`elastos-server/src/resource_bridge.rs:503-524`, `594-604`) and the
//! localhost provider (`elastos/capsules/localhost-provider/src/main.rs:403-476`,
//! `783-807`).

use std::fmt;

use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::json;

/// The `bus-error` variants of `elastos-bus-v1.wit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BusFailure {
    Denied(String),
    NotFound(String),
    Invalid(String),
    Unavailable(String),
    Timeout(String),
    Internal(String),
}

impl BusFailure {
    pub fn message(&self) -> &str {
        match self {
            BusFailure::Denied(message)
            | BusFailure::NotFound(message)
            | BusFailure::Invalid(message)
            | BusFailure::Unavailable(message)
            | BusFailure::Timeout(message)
            | BusFailure::Internal(message) => message,
        }
    }
}

pub struct InvokeReply {
    pub status: String,
    pub body: Vec<u8>,
}

pub trait Bus {
    /// `capabilities.request` with exactly one action. Returns the grant id.
    fn request(&mut self, resource: &str, action: &str, reason: &str)
        -> Result<String, BusFailure>;

    /// `providers.invoke` with a JSON body and a grant.
    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure>;
}

/// Why a read or write through the Bus did not produce bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The Runtime refused or failed the call.
    Bus(BusFailure),
    /// The provider answered with `status: error`.
    Provider { code: String, message: String },
    /// The answer did not have the documented shape.
    Shape(String),
}

/// Reads `length` bytes at `offset`. A short or empty answer means the
/// object ends there.
pub fn read_window(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, CallError> {
    let body = json!({ "path": uri, "offset": offset, "length": length }).to_string();
    let reply = bus
        .invoke(uri, "read", body.as_bytes(), grant)
        .map_err(CallError::Bus)?;
    let content = ok_reply(&reply)?
        .content
        .ok_or_else(|| CallError::Shape("read answer has no content array".into()))?;
    if content.len() as u64 > length {
        return Err(CallError::Shape(format!(
            "read answer has {} bytes, asked for at most {length}",
            content.len()
        )));
    }
    Ok(content)
}

/// Writes `content` as the whole object.
///
/// `content` goes as a byte array with `append: false`. Runtime's principal
/// root write accepts bytes or a string (`resource_bridge.rs:583-592`), but the
/// localhost provider takes only bytes and requires `append`
/// (`elastos/capsules/localhost-provider/src/main.rs:25`, `42-48`).
pub fn write_bytes(
    bus: &mut dyn Bus,
    uri: &str,
    grant: &str,
    content: &[u8],
) -> Result<(), CallError> {
    let body = json!({ "path": uri, "content": content, "append": false }).to_string();
    let reply = bus
        .invoke(uri, "write", body.as_bytes(), grant)
        .map_err(CallError::Bus)?;
    ok_reply(&reply).map(|_| ())
}

fn ok_reply(reply: &InvokeReply) -> Result<Reply, CallError> {
    let parsed: Reply = serde_json::from_slice(&reply.body)
        .map_err(|err| CallError::Shape(format!("provider answer is malformed: {err}")))?;
    match parsed.status.as_deref() {
        Some("ok") if parsed.has_data => Ok(parsed),
        Some("ok") => Err(CallError::Shape("provider answer has no data".into())),
        Some("error") => Err(CallError::Provider {
            code: parsed.code.unwrap_or_else(|| "unknown".to_string()),
            message: parsed.message.unwrap_or_default(),
        }),
        _ => Err(CallError::Shape(format!(
            "provider answer has status {:?}",
            reply.status
        ))),
    }
}

/// A provider answer parsed in one pass. Read content goes straight into
/// bytes, and every field the guest does not use is skipped without building
/// a value: a `serde_json::Value` per byte costs too much fuel.
#[derive(Default)]
struct Reply {
    status: Option<String>,
    code: Option<String>,
    message: Option<String>,
    has_data: bool,
    content: Option<Vec<u8>>,
}

/// The `data` object of an answer. Only `content` is kept.
struct Data {
    content: Option<Vec<u8>>,
}

impl<'de> Deserialize<'de> for Reply {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ReplyVisitor;
        impl<'de> Visitor<'de> for ReplyVisitor {
            type Value = Reply;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a provider result object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Reply, A::Error> {
                let mut reply = Reply::default();
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "status" => reply.status = Some(map.next_value()?),
                        "code" => reply.code = Some(map.next_value()?),
                        "message" => reply.message = Some(map.next_value()?),
                        "data" => {
                            reply.has_data = true;
                            reply.content = map.next_value::<Data>()?.content;
                        }
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(reply)
            }
        }
        deserializer.deserialize_map(ReplyVisitor)
    }
}

impl<'de> Deserialize<'de> for Data {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DataVisitor;
        impl<'de> Visitor<'de> for DataVisitor {
            type Value = Data;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a provider data object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Data, A::Error> {
                let mut content = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "content" {
                        content = Some(map.next_value::<Vec<u8>>()?);
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(Data { content })
            }
        }
        deserializer.deserialize_map(DataVisitor)
    }
}
