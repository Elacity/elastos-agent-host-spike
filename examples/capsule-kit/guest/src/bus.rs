//! The two Bus calls a guest makes, behind a trait so host tests can fake
//! the Runtime.
//!
//! On wasm32 the trait is implemented over the `elastos:bus@v1` imports
//! (`component`, feature `wit`). The
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
use serde_json::{json, Value};

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

/// The Runtime's digest of one launch content file. The core judges the
/// size against its listing and the sha256 shape; this helper does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Digest {
    pub path: String,
    pub size: u64,
    pub algorithm: String,
    pub sha256: String,
}

/// Asks the Runtime for the digest of one launch content file.
///
/// The body is exactly `{"path": uri}`: the digest covers the whole file and
/// ignores `offset`/`length` (ruling r3 §8 A4). The answer is parsed with
/// `serde_json::Value`: it is about 200 bytes, so a typed visitor buys no
/// fuel, and the one-pass `Reply`/`Data` visitors that carry read content
/// stay byte-identical.
pub fn digest(bus: &mut dyn Bus, uri: &str, grant: &str) -> Result<Digest, CallError> {
    let body = json!({ "path": uri }).to_string();
    let reply = bus
        .invoke(uri, "digest", body.as_bytes(), grant)
        .map_err(CallError::Bus)?;
    let answer: Value = serde_json::from_slice(&reply.body)
        .map_err(|err| CallError::Shape(format!("provider answer is malformed: {err}")))?;
    match answer["status"].as_str() {
        Some("ok") => {}
        Some("error") => {
            return Err(CallError::Provider {
                code: answer["code"].as_str().unwrap_or("unknown").to_string(),
                message: answer["message"].as_str().unwrap_or_default().to_string(),
            })
        }
        _ => {
            return Err(CallError::Shape(format!(
                "provider answer has status {:?}",
                answer["status"]
            )))
        }
    }
    let data = answer["data"]
        .as_object()
        .ok_or_else(|| CallError::Shape("digest answer has no data object".into()))?;
    let field = |name: &str| {
        data.get(name)
            .ok_or_else(|| CallError::Shape(format!("digest answer has no {name}")))
    };
    let path = field("path")?
        .as_str()
        .ok_or_else(|| CallError::Shape("digest answer path must be a string".into()))?;
    let size = field("size")?
        .as_u64()
        .ok_or_else(|| CallError::Shape("digest answer size must be a number".into()))?;
    let algorithm = field("algorithm")?
        .as_str()
        .ok_or_else(|| CallError::Shape("digest answer algorithm must be a string".into()))?;
    let sha256 = field("sha256")?
        .as_str()
        .ok_or_else(|| CallError::Shape("digest answer sha256 must be a string".into()))?;
    if path != uri {
        return Err(CallError::Shape(format!(
            "digest answer names {path}, asked {uri}"
        )));
    }
    Ok(Digest {
        path: path.to_string(),
        size,
        algorithm: algorithm.to_string(),
        sha256: sha256.to_string(),
    })
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
    let reply = bus
        .invoke(uri, "write", write_body(uri, content).as_bytes(), grant)
        .map_err(CallError::Bus)?;
    ok_reply(&reply).map(|_| ())
}

/// `{"append":false,"content":[..],"path":".."}`, written straight into a
/// string: the same bytes `json!` gives with its sorted keys, without a
/// `serde_json::Value` per byte, which costs more fuel than anything else in
/// a run once the output is large.
pub fn write_body(uri: &str, content: &[u8]) -> String {
    let path = serde_json::to_string(uri).expect("a string always serializes");
    let mut body = String::with_capacity(content.len() * 4 + path.len() + 40);
    body.push_str(r#"{"append":false,"content":["#);
    for (index, byte) in content.iter().enumerate() {
        if index > 0 {
            body.push(',');
        }
        if *byte >= 100 {
            body.push(char::from(b'0' + byte / 100));
        }
        if *byte >= 10 {
            body.push(char::from(b'0' + byte / 10 % 10));
        }
        body.push(char::from(b'0' + byte % 10));
    }
    body.push_str(r#"],"path":"#);
    body.push_str(&path);
    body.push('}');
    body
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
