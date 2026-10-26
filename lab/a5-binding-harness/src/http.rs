//! The operator adapter: the journeys' calls as shell requests on the
//! routes SPEC.md names. It reaches only IPv4 loopback, keeps the attach
//! secret and session token in memory, and bounds every response.
//!
//! Until the RA-* gaps close, [`crate::acceptance`] never constructs this
//! type. A later real-Runtime run sets `A5_RUNTIME_COORDS` and the journeys
//! call through here.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::contract::{
    Actor, BindingRuntime, Caller, EvidenceKind, Fixture, Grant, Instance, LiveGrant, PublicRead,
    RuntimeEvidence, UseOutcome, PUBLIC_RESOURCE,
};

pub const COORDS_VAR: &str = "A5_RUNTIME_COORDS";

const HTTP_BOUND: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;

/// What a live run needs: the operator's coordinates file.
pub struct Setup {
    coords: PathBuf,
}

impl Setup {
    pub fn from_env() -> Result<Setup, String> {
        Setup::from_lookup(|name| std::env::var_os(name).map(PathBuf::from))
    }

    pub fn from_lookup(lookup: impl Fn(&str) -> Option<PathBuf>) -> Result<Setup, String> {
        let value = lookup(COORDS_VAR).ok_or(format!("{COORDS_VAR} is not set"))?;
        if !value.is_absolute() {
            return Err(format!("{COORDS_VAR} must be an absolute path"));
        }
        if !value.is_file() {
            return Err(format!("{COORDS_VAR} names no file"));
        }
        Ok(Setup { coords: value })
    }
}

pub struct Coords {
    pub port: u16,
    secret: String,
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or(format!("missing string field {field}"))
}

pub fn parse_coords(bytes: &[u8]) -> Result<Coords, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "the coordinates are not JSON".to_owned())?;
    let port = text(&value, "api_url")?
        .strip_prefix("http://127.0.0.1:")
        .ok_or("the operator API must be http://127.0.0.1:<port>")?
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or("the operator API port is invalid")?;
    if text(&value, "runtime_kind")? != "operator" {
        return Err("the coordinates belong to a Runtime that is not an operator".to_owned());
    }
    let secret = text(&value, "attach_secret")?.to_owned();
    if secret.is_empty() {
        return Err("the coordinates hold an empty attach secret".to_owned());
    }
    Ok(Coords { port, secret })
}

fn header_safe(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic())
}

pub fn parse_response(bytes: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("the response lacks HTTP headers")?;
    let head = std::str::from_utf8(&bytes[..split]).map_err(|_| "invalid response headers")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("invalid HTTP status line")?;
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or("invalid response header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported response transfer encoding".to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("repeated response length".to_owned());
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid response length")?,
            );
        }
    }
    let body = &bytes[split + 4..];
    if length != Some(body.len()) {
        return Err("response length mismatch".to_owned());
    }
    Ok((status, body.to_vec()))
}

fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(u16, Vec<u8>), String> {
    let fail = |what: &str| format!("{method} {path}: {what}");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, HTTP_BOUND)
        .map_err(|_| fail("loopback connect failed"))?;
    stream
        .set_write_timeout(Some(HTTP_BOUND))
        .map_err(|_| fail("cannot bound the write"))?;
    let encoded = match body {
        Some(body) => Some(serde_json::to_vec(body).map_err(|_| fail("cannot encode the body"))?),
        None => None,
    };
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(token) = token {
        if !header_safe(token) {
            return Err(fail("session token cannot be sent as a header"));
        }
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(encoded) = &encoded {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", encoded.len()));
    } else {
        request.push_str("Content-Length: 0\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| fail("write headers failed"))?;
    if let Some(encoded) = &encoded {
        stream
            .write_all(encoded)
            .map_err(|_| fail("write body failed"))?;
    }
    stream.flush().map_err(|_| fail("flush failed"))?;
    stream
        .set_read_timeout(Some(HTTP_BOUND))
        .map_err(|_| fail("cannot bound the read"))?;
    let mut bytes = Vec::new();
    let started = Instant::now();
    loop {
        if started.elapsed() > HTTP_BOUND {
            return Err(fail("read timed out"));
        }
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                bytes.extend_from_slice(&buf[..n]);
                if bytes.len() > MAX_RESPONSE {
                    return Err(fail("response too large"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                return Err(fail("read timed out"));
            }
            Err(_) => return Err(fail("read failed")),
        }
    }
    parse_response(&bytes)
}

/// Live operator. Binding evidence is recorded only from HTTP answers.
pub struct OperatorRuntime {
    port: u16,
    token: String,
    evidence: Option<RuntimeEvidence>,
}

impl OperatorRuntime {
    pub fn attach(setup: &Setup) -> Result<Self, String> {
        let bytes = std::fs::read(&setup.coords)
            .map_err(|_| format!("cannot read {}", setup.coords.display()))?;
        let coords = parse_coords(&bytes)?;
        let attach = json!({"secret": coords.secret, "scope": "shell"});
        let (status, body) = http(coords.port, "POST", "/api/auth/attach", None, Some(&attach))?;
        if status != 200 {
            return Err(format!("POST /api/auth/attach returned HTTP {status}"));
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| "the attach answer is not JSON".to_owned())?;
        let token = text(&value, "token")?.to_owned();
        if token.is_empty() {
            return Err("the attach did not open a shell session".to_owned());
        }
        if !header_safe(&token) {
            return Err("the attach token cannot be sent as a header".to_owned());
        }
        Ok(Self {
            port: coords.port,
            token,
            evidence: None,
        })
    }

    pub fn take_binding_evidence(&mut self) -> Option<RuntimeEvidence> {
        self.evidence.take()
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        let (status, bytes) = http(self.port, method, path, Some(&self.token), body)?;
        if bytes.is_empty() {
            return Ok((status, Value::Null));
        }
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, value))
    }

    fn record(&mut self, evidence: RuntimeEvidence) {
        self.evidence = Some(evidence);
    }
}

impl BindingRuntime for OperatorRuntime {
    fn health(&mut self) -> Result<(), String> {
        let (status, value) = self.call("GET", "/api/health", None)?;
        if status != 200 || value["status"] != "ok" {
            return Err(format!("GET /api/health returned HTTP {status}"));
        }
        Ok(())
    }

    fn launch(&mut self, identity: &str, _fixture: Fixture) -> Result<Instance, String> {
        let (status, value) = self.call(
            "POST",
            "/api/capsules",
            Some(&json!({"path": format!("a5-binding/{identity}")})),
        )?;
        let session = value["session_id"].as_str().unwrap_or("");
        let id = value["id"].as_str().unwrap_or("");
        if session.is_empty() || value["status"] == "completed" {
            return Err(format!(
                "POST /api/capsules returned HTTP {status} status={} session empty={}; missing RA-6",
                value["status"],
                session.is_empty()
            ));
        }
        Ok(Instance {
            id: id.to_owned(),
            identity: identity.to_owned(),
            session: session.to_owned(),
        })
    }

    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String> {
        let (status, _) = self.call(
            "DELETE",
            &format!("/api/capsules/{id}"),
            Some(&json!({"reason": reason})),
        )?;
        if status != 200 {
            return Err(format!(
                "DELETE /api/capsules/{id} returned HTTP {status}; missing RA-6"
            ));
        }
        Ok(())
    }

    fn end_session(&mut self, session: &str) -> Result<(), String> {
        let (status, _) = self.call(
            "POST",
            &format!("/api/sessions/{session}/end"),
            Some(&json!({})),
        )?;
        if status != 200 {
            return Err(format!(
                "POST /api/sessions/{session}/end returned HTTP {status}; missing RA-2"
            ));
        }
        Ok(())
    }

    fn mint_grant(&mut self, instance: &Instance, resource: &str) -> Result<Grant, String> {
        let (status, value) = self.call(
            "POST",
            "/api/capability/grant",
            Some(&json!({
                "session_id": instance.session,
                "resource": resource,
                "action": "read"
            })),
        )?;
        let id = value["request_id"].as_str().or(value["id"].as_str());
        let owned = value["owned_root"].as_str().unwrap_or("");
        let identity = value["identity"].as_str().unwrap_or("");
        if status != 200 || id.is_none() || owned.is_empty() || identity.is_empty() {
            return Err(format!(
                "POST /api/capability/grant returned HTTP {status} without identity/owned_root; missing RA-1, RA-5"
            ));
        }
        Ok(Grant {
            id: id.unwrap().to_owned(),
            identity: identity.to_owned(),
            session: instance.session.clone(),
            instance: instance.id.clone(),
            owned_root: owned.to_owned(),
            resource: resource.to_owned(),
        })
    }

    fn use_grant(
        &mut self,
        caller: &Caller,
        grant: &Grant,
        path: &str,
    ) -> Result<UseOutcome, String> {
        let (status, value) = self.call(
            "POST",
            "/api/capability/use",
            Some(&json!({
                "grant_id": grant.id,
                "identity": caller.identity,
                "session": caller.session,
                "instance": caller.instance,
                "path": path
            })),
        )?;
        let reason = value["reason"]
            .as_str()
            .or(value["message"].as_str())
            .unwrap_or("")
            .to_owned();
        let request_id = value["request_id"].as_str().map(str::to_owned);
        if status == 200 && value["status"] != "denied" {
            let evidence = RuntimeEvidence::from_operator(
                EvidenceKind::Allowed,
                status,
                request_id.or_else(|| Some(grant.id.clone())),
                reason,
                Actor::Runtime,
                path.to_owned(),
                Some(caller.identity.clone()),
                Some(caller.session.clone()),
                Some(caller.instance.clone()),
            );
            self.record(evidence.clone());
            return Ok(UseOutcome::Allowed { evidence });
        }
        if status == 0 {
            return Err("POST /api/capability/use produced no HTTP status; missing RA-1".to_owned());
        }
        let evidence = RuntimeEvidence::from_operator(
            EvidenceKind::Refused,
            status,
            request_id.or_else(|| Some(grant.id.clone())),
            if reason.is_empty() {
                format!("HTTP {status}")
            } else {
                reason
            },
            Actor::Runtime,
            path.to_owned(),
            Some(caller.identity.clone()),
            Some(caller.session.clone()),
            Some(caller.instance.clone()),
        );
        self.record(evidence.clone());
        Ok(UseOutcome::Refused { evidence })
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        let (status, value) =
            self.call("GET", "/api/capability/list?scope=all_sessions_live", None)?;
        if status != 200 || value["scope"] != "all_sessions_live" {
            return Err(format!(
                "GET /api/capability/list?scope=all_sessions_live returned HTTP {status} scope={}; missing RA-1",
                value["scope"]
            ));
        }
        let mut grants = Vec::new();
        for item in value["capabilities"].as_array().cloned().unwrap_or_default() {
            grants.push(LiveGrant {
                request_id: item["request_id"].as_str().unwrap_or("").to_owned(),
                identity: item["identity"].as_str().unwrap_or("").to_owned(),
                session: item["session_id"].as_str().unwrap_or("").to_owned(),
                instance: item["instance_id"].as_str().unwrap_or("").to_owned(),
                resource: item["resource"].as_str().unwrap_or("").to_owned(),
                owned_root: item["owned_root"].as_str().unwrap_or("").to_owned(),
            });
        }
        Ok(grants)
    }

    fn public_read(&mut self, path: &str) -> Result<PublicRead, String> {
        let resource = if path.is_empty() {
            PUBLIC_RESOURCE
        } else {
            path
        };
        let (_status, _value) = self.call(
            "POST",
            "/api/provider/localhost/write",
            Some(&json!({
                "uri": resource,
                "content": "a5-binding public fixture bytes\n"
            })),
        )?;
        // A write/read of Public may work today. It is never binding.
        Ok(PublicRead {
            resource: resource.to_owned(),
            bytes: b"a5-binding public fixture bytes\n".to_vec(),
            bound: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coords_requires_loopback_operator() {
        let ok = json!({
            "api_url": "http://127.0.0.1:61180",
            "runtime_kind": "operator",
            "attach_secret": "synthetic-secret"
        });
        let coords = parse_coords(ok.to_string().as_bytes()).unwrap();
        assert_eq!(coords.port, 61180);
        let bad = json!({
            "api_url": "http://10.0.0.1:80",
            "runtime_kind": "operator",
            "attach_secret": "synthetic-secret"
        });
        assert!(parse_coords(bad.to_string().as_bytes()).is_err());
    }

    #[test]
    fn parse_response_reads_status_and_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (status, body) = parse_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"ok");
    }

    #[test]
    fn setup_without_coords_is_skipped_reason() {
        let err = Setup::from_lookup(|_| None).unwrap_err();
        assert!(err.contains(COORDS_VAR), "{err}");
    }

    #[test]
    fn owned_root_shape_matches_spec() {
        assert_eq!(
            crate::contract::owned_root("agent-a", "session-1", "inst-1"),
            "UsersAI/agent-a/session-1/inst-1"
        );
    }
}
