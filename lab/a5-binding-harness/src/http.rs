//! The operator adapter: the journeys' calls as shell requests on routes
//! that exist on elastos-runtime develop (92aeea44 or newer).
//!
//! The guest presents a handle. This adapter never sends identity, session
//! or instance as client JSON. Missing routes are named as Runtime asks.
//!
//! Present on develop: `GET /api/health`, `POST /api/auth/attach`,
//! `POST /api/capsules`, `DELETE /api/capsules/:id`,
//! `POST /api/capability/request`, `POST /api/capability/grant` (body
//! `request_id`), `GET /api/capability/list`,
//! `GET /api/capability/request/:id`, `GET`/`PUT /api/localhost/*path`.
//!
//! Absent, named as asks: guest-handle use (not on develop), session-end
//! (RA-2), host-record-for-handle (RA-1 / #463), launch handle (RA-6).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::contract::{
    require_grant_id, BindingRuntime, Fixture, Grant, Handle, HostBinding, Instance, LiveGrant,
    PublicRead, RequestRecord, RuntimeEvidence, UseOutcome, PUBLIC_RESOURCE,
};

pub const COORDS_VAR: &str = "A5_RUNTIME_COORDS";

const HTTP_BOUND: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;

/// What a live run needs: the operator's coordinates file.
#[derive(Debug)]
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
    body: Option<&[u8]>,
    content_type: Option<&str>,
) -> Result<(u16, Vec<u8>), String> {
    let fail = |what: &str| format!("{method} {path}: {what}");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, HTTP_BOUND)
        .map_err(|_| fail("loopback connect failed"))?;
    stream
        .set_write_timeout(Some(HTTP_BOUND))
        .map_err(|_| fail("cannot bound the write"))?;
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(token) = token {
        if !header_safe(token) {
            return Err(fail("session token cannot be sent as a header"));
        }
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(encoded) = body {
        request.push_str(&format!(
            "Content-Type: {}\r\n",
            content_type.unwrap_or("application/octet-stream")
        ));
        request.push_str(&format!("Content-Length: {}\r\n", encoded.len()));
    } else {
        request.push_str("Content-Length: 0\r\n");
    }
    request.push_str("Connection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|_| fail("write headers failed"))?;
    if let Some(encoded) = body {
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

/// True when the operator body claims grant-binding fields. Raw Public file
/// bytes are not a bind. The flag is derived, never hardcoded.
pub fn public_binding_claim(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    value.get("grant_id").is_some()
        || value.get("owned_root").is_some()
        || value.get("identity").is_some()
        || value.get("instance_id").is_some()
        || value.get("session_id").is_some()
}

/// Live operator. Binding evidence is recorded only from HTTP answers that
/// carry a guest handle.
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
        let encoded = serde_json::to_vec(&attach).map_err(|_| "cannot encode attach".to_owned())?;
        let (status, body) = http(
            coords.port,
            "POST",
            "/api/auth/attach",
            None,
            Some(&encoded),
            Some("application/json"),
        )?;
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

    fn call_raw(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Result<(u16, Vec<u8>), String> {
        http(
            self.port,
            method,
            path,
            Some(&self.token),
            body,
            content_type,
        )
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), String> {
        let encoded = match body {
            Some(body) => {
                Some(serde_json::to_vec(body).map_err(|_| "cannot encode the body".to_owned())?)
            }
            None => None,
        };
        let (status, bytes) = self.call_raw(
            method,
            path,
            encoded.as_deref(),
            body.map(|_| "application/json"),
        )?;
        if bytes.is_empty() {
            return Ok((status, Value::Null));
        }
        let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok((status, value))
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

    fn launch(&mut self, _identity: &str, fixture: Fixture) -> Result<Instance, String> {
        let (status, value) = self.call(
            "POST",
            "/api/capsules",
            Some(&json!({"path": format!("a5-binding/{}", fixture.name())})),
        )?;
        let handle = value["handle"].as_str().unwrap_or("");
        let id = value["id"].as_str().unwrap_or("");
        if handle.is_empty() || value["status"] == "completed" {
            return Err(format!(
                "POST /api/capsules returned HTTP {status} status={} handle empty={}; missing RA-6 / #463 guest handle",
                value["status"],
                handle.is_empty()
            ));
        }
        Ok(Instance {
            id: id.to_owned(),
            handle: Handle::new(handle)?,
        })
    }

    fn host_record(&mut self, _handle: &Handle) -> Result<HostBinding, String> {
        Err(
            "no host-record-for-handle route on develop; guest presents a handle (RA-1 / #463)"
                .to_owned(),
        )
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

    fn end_session(&mut self, _handle: &Handle) -> Result<(), String> {
        Err("session end route is absent on develop (RA-2)".to_owned())
    }

    fn mint_grant(&mut self, handle: &Handle, resource: &str) -> Result<Grant, String> {
        if crate::contract::is_public_resource(resource) {
            return Err(crate::contract::PUBLIC_REASON.to_owned());
        }
        let (req_status, req_value) = self.call(
            "POST",
            "/api/capability/request",
            Some(&json!({
                "resource": resource,
                "action": "read",
                "reason": "a5-binding harness"
            })),
        )?;
        let request_id = req_value["request_id"].as_str().unwrap_or("");
        if req_status != 200 || request_id.is_empty() {
            return Err(format!(
                "POST /api/capability/request returned HTTP {req_status} without request_id"
            ));
        }
        require_grant_id(request_id)?;
        let (status, value) = self.call(
            "POST",
            "/api/capability/grant",
            Some(&json!({
                "request_id": request_id,
                "duration": "session",
                "rationale": "a5-binding harness"
            })),
        )?;
        if status != 200 || value["success"] != true {
            return Err(format!(
                "POST /api/capability/grant returned HTTP {status} without success for request_id"
            ));
        }
        Ok(Grant {
            id: request_id.to_owned(),
            handle: handle.clone(),
            resource: resource.to_owned(),
        })
    }

    fn use_grant(
        &mut self,
        _handle: &Handle,
        _grant: &Grant,
        _path: &str,
    ) -> Result<UseOutcome, String> {
        Err("guest-handle use route is absent on develop (RA-1 / #463)".to_owned())
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        let (status, value) = self.call("GET", "/api/capability/list", None)?;
        if status != 200 {
            return Err(format!(
                "GET /api/capability/list returned HTTP {status}; missing RA-1"
            ));
        }
        let mut grants = Vec::new();
        for item in value["capabilities"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let request_id = item["request_id"].as_str().unwrap_or("");
            require_grant_id(request_id)?;
            let identity = item["identity"].as_str().unwrap_or("");
            let session = item["session_id"].as_str().unwrap_or("");
            let instance = item["instance_id"].as_str().unwrap_or("");
            let owned_root = item["owned_root"].as_str().unwrap_or("");
            if identity.is_empty()
                || session.is_empty()
                || instance.is_empty()
                || owned_root.is_empty()
            {
                return Err(
                    "GET /api/capability/list has no identity/session/instance/owned_root; missing RA-1"
                        .to_owned(),
                );
            }
            grants.push(LiveGrant {
                request_id: request_id.to_owned(),
                identity: identity.to_owned(),
                session: session.to_owned(),
                instance: instance.to_owned(),
                resource: item["resource"].as_str().unwrap_or("").to_owned(),
                owned_root: owned_root.to_owned(),
            });
        }
        Ok(grants)
    }

    fn request_record(&mut self, request_id: &str) -> Result<RequestRecord, String> {
        require_grant_id(request_id)?;
        let (status, value) = self.call(
            "GET",
            &format!("/api/capability/request/{request_id}"),
            None,
        )?;
        if status != 200 {
            return Err(format!(
                "GET /api/capability/request/{request_id} returned HTTP {status}; missing RA-2 settled_by"
            ));
        }
        Ok(RequestRecord {
            request_id: request_id.to_owned(),
            status: value["status"].as_str().unwrap_or("").to_owned(),
            settled_by: value["settled_by"].as_str().map(str::to_owned),
        })
    }

    fn public_read(&mut self, path: &str) -> Result<PublicRead, String> {
        let resource = if path.is_empty() {
            PUBLIC_RESOURCE
        } else {
            path
        };
        let rest = resource.strip_prefix("localhost://").unwrap_or(resource);
        let fixture = b"a5-binding public fixture bytes\n";
        let put_path = format!("/api/localhost/{rest}");
        let (_put_status, _) =
            self.call_raw("PUT", &put_path, Some(fixture), Some("text/plain"))?;
        let (status, body) = self.call_raw("GET", &put_path, None, None)?;
        if status != 200 {
            return Err(format!(
                "GET /api/localhost/{rest} returned HTTP {status}; Public was not read"
            ));
        }
        Ok(PublicRead {
            resource: resource.to_owned(),
            bytes: body.clone(),
            bound: public_binding_claim(&body),
        })
    }

    fn seed(&mut self, _handle: &Handle, rel: &str, bytes: &[u8]) -> Result<(), String> {
        Err(format!(
            "seed of {rel} ({} bytes) needs a host-record owned root; missing RA-1 / RA-5 / RA-6",
            bytes.len()
        ))
    }

    fn read_bytes(&mut self, _handle: &Handle, rel: &str) -> Result<Vec<u8>, String> {
        Err(format!(
            "read of {rel} needs a host-record owned root; missing RA-1 / RA-5 / RA-6"
        ))
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

    #[test]
    fn public_read_bound_is_not_hardcoded() {
        assert!(
            !public_binding_claim(b"a5-binding public fixture bytes\n"),
            "raw Public bytes are not a bind"
        );
        let forged = serde_json::json!({
            "grant_id": "public-claim",
            "identity": "agent-a",
            "bound": true
        });
        assert!(
            public_binding_claim(forged.to_string().as_bytes()),
            "an operator body that claims grant_id must be bound"
        );
    }

    #[test]
    fn http_adapter_does_not_invent_missing_routes_or_client_identity() {
        let src = include_str!("http.rs")
            .split("mod tests")
            .next()
            .expect("http adapter source");
        assert!(
            !src.contains("\"/api/capability/use\""),
            "must not call a guest-handle use route that is absent on develop"
        );
        assert!(
            !src.contains("/api/sessions/"),
            "must not call a session-end route that is absent on develop"
        );
        assert!(src.contains("/api/capability/grant"), "grant route exists");
        assert!(
            src.contains("\"request_id\""),
            "grant body must send request_id"
        );
        assert!(
            !src.contains("\"identity\": caller"),
            "must not send identity as client JSON"
        );
        assert!(
            !src.contains("\"session\": caller"),
            "must not send session as client JSON"
        );
        assert!(
            !src.contains("\"instance\": caller"),
            "must not send instance as client JSON"
        );
        assert!(
            !src.contains("bound: false"),
            "Public bound must not be hardcoded false"
        );
        assert!(
            src.contains("public_binding_claim"),
            "Public bound is derived from the operator body"
        );
    }
}
