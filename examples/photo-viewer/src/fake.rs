//! A fake Runtime for host tests.
//!
//! It mirrors the bridge contract the guest depends on:
//! - a grant is issued only for a (resource, action) pair the test allows;
//! - `invoke` without a matching grant is `Denied`, as at
//!   `elastos-server/src/resource_bridge.rs:364-409`;
//! - `read` applies the offset/length window of `resource_bridge.rs:594-604`
//!   and answers `{"status":"ok","data":{"content":[..],"size":n}}`;
//! - `write` stores the `content` string and answers `bytes_written`.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::{Bus, BusFailure, InvokeReply};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Request {
        resource: String,
        action: String,
    },
    Invoke {
        resource: String,
        operation: String,
        body: Value,
    },
}

#[derive(Default)]
pub struct FakeBus {
    pub objects: BTreeMap<String, Vec<u8>>,
    pub allowed: BTreeSet<(String, String)>,
    pub provider_errors: BTreeMap<String, (String, String)>,
    pub written: BTreeMap<String, String>,
    pub calls: Vec<Call>,
    issued: BTreeMap<String, (String, String)>,
}

impl FakeBus {
    pub fn object(mut self, uri: &str, bytes: Vec<u8>) -> Self {
        self.objects.insert(uri.to_string(), bytes);
        self
    }

    pub fn allow(mut self, uri: &str, action: &str) -> Self {
        self.allowed.insert((uri.to_string(), action.to_string()));
        self
    }

    pub fn provider_error(mut self, uri: &str, code: &str, message: &str) -> Self {
        self.provider_errors
            .insert(uri.to_string(), (code.to_string(), message.to_string()));
        self
    }

    pub fn invokes_on(&self, uri: &str) -> Vec<&Call> {
        self.calls
            .iter()
            .filter(|call| matches!(call, Call::Invoke { resource, .. } if resource == uri))
            .collect()
    }

    /// Total content bytes handed to the guest for one object.
    pub fn bytes_served(&self, uri: &str) -> u64 {
        self.invokes_on(uri)
            .iter()
            .filter_map(|call| match call {
                Call::Invoke {
                    operation, body, ..
                } if operation == "read" => {
                    let size = self.objects.get(uri).map_or(0, |bytes| bytes.len() as u64);
                    let offset = body["offset"].as_u64().unwrap_or(0);
                    let length = body["length"].as_u64().unwrap_or(u64::MAX);
                    Some(size.saturating_sub(offset).min(length))
                }
                _ => None,
            })
            .sum()
    }
}

fn reply(result: Value) -> InvokeReply {
    InvokeReply {
        status: result["status"].as_str().unwrap_or("ok").to_string(),
        body: serde_json::to_vec(&result).unwrap(),
    }
}

impl Bus for FakeBus {
    fn request(
        &mut self,
        resource: &str,
        action: &str,
        _reason: &str,
    ) -> Result<String, BusFailure> {
        self.calls.push(Call::Request {
            resource: resource.to_string(),
            action: action.to_string(),
        });
        if !self
            .allowed
            .contains(&(resource.to_string(), action.to_string()))
        {
            return Err(BusFailure::Denied(format!(
                "no {action} grant for {resource}"
            )));
        }
        let id = format!("grant-{}", self.issued.len() + 1);
        self.issued
            .insert(id.clone(), (resource.to_string(), action.to_string()));
        Ok(id)
    }

    fn invoke(
        &mut self,
        resource: &str,
        operation: &str,
        body: &[u8],
        grant: &str,
    ) -> Result<InvokeReply, BusFailure> {
        let body: Value = serde_json::from_slice(body).map_err(|err| {
            BusFailure::Invalid(format!("component invoke body must be JSON: {err}"))
        })?;
        self.calls.push(Call::Invoke {
            resource: resource.to_string(),
            operation: operation.to_string(),
            body: body.clone(),
        });
        let action = match operation {
            "read" => "read",
            "write" => "write",
            other => {
                return Err(BusFailure::Invalid(format!(
                    "unsupported operation {other}"
                )))
            }
        };
        match self.issued.get(grant) {
            Some((granted, granted_action)) if granted == resource && granted_action == action => {}
            _ => {
                return Err(BusFailure::Denied(
                    "Capability validation failed".to_string(),
                ))
            }
        }
        if body["path"].as_str() != Some(resource) {
            return Err(BusFailure::Invalid("path must equal the resource".into()));
        }
        if let Some((code, message)) = self.provider_errors.get(resource) {
            return Ok(reply(
                json!({ "status": "error", "code": code, "message": message }),
            ));
        }
        match operation {
            "read" => {
                let Some(bytes) = self.objects.get(resource) else {
                    return Ok(reply(json!({
                        "status": "error",
                        "code": "read_failed",
                        "message": "object not found",
                    })));
                };
                let start = body["offset"].as_u64().unwrap_or(0) as usize;
                let window = if start >= bytes.len() {
                    Vec::new()
                } else {
                    let end = match body["length"].as_u64() {
                        Some(length) => start.saturating_add(length as usize).min(bytes.len()),
                        None => bytes.len(),
                    };
                    bytes[start..end].to_vec()
                };
                Ok(reply(json!({
                    "status": "ok",
                    "data": { "content": window, "size": window.len() },
                })))
            }
            _ => {
                let content = body["content"]
                    .as_str()
                    .ok_or_else(|| BusFailure::Invalid("write content must be a string".into()))?;
                self.written
                    .insert(resource.to_string(), content.to_string());
                Ok(reply(json!({
                    "status": "ok",
                    "data": { "bytes_written": content.len() },
                })))
            }
        }
    }
}
