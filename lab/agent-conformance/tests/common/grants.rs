//! The fixture's one shell approver. Credentials and HTTP bodies stay in memory.

use agent_conformance::harness::ThrowawayHome;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, &'static str>;

pub struct Fixture {
    deny_reason: String,
    entries: Vec<Value>,
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or("grant protocol requires a nonempty string field")
}

impl Fixture {
    pub fn committed() -> Result<Self> {
        Self::parse(include_str!("../../fixtures/grants.json"))
    }

    fn parse(text: &str) -> Result<Self> {
        let value: Value = serde_json::from_str(text).map_err(|_| "invalid grant fixture JSON")?;
        let deny_reason = field(&value, "deny_reason")?.to_owned();
        let entries = value["grants"]
            .as_array()
            .ok_or("grant fixture requires entries")?
            .clone();
        let mut unique = BTreeSet::new();
        for entry in &entries {
            let resource = field(entry, "resource")?;
            let action = field(entry, "action")?;
            let reason = field(entry, "reason")?;
            if !matches!(field(entry, "duration")?, "once" | "session") {
                return Err("grant fixture duration must be once or session");
            }
            if !unique.insert((resource, action, reason)) {
                return Err("grant fixture repeats an exact match");
            }
        }
        Ok(Self {
            deny_reason,
            entries,
        })
    }

    fn matches(&self, request: &Value) -> Result<Option<usize>> {
        let resource = field(request, "resource")?;
        let action = field(request, "action")?;
        let reason = field(request, "reason")?;
        Ok(self.entries.iter().position(|entry| {
            entry["resource"] == resource && entry["action"] == action && entry["reason"] == reason
        }))
    }

    // Inspect the whole snapshot before making any decision. An entry already
    // consumed by this controller also refuses a later matching request.
    fn decisions(&self, pending: &[Value], used: &BTreeSet<usize>) -> Result<Vec<Option<usize>>> {
        let matched: Vec<_> = pending
            .iter()
            .map(|r| self.matches(r))
            .collect::<Result<_>>()?;
        for index in matched.iter().flatten() {
            if used.contains(index) || matched.iter().filter(|m| **m == Some(*index)).count() != 1 {
                return Err("ambiguous fixture grant: an entry matches multiple requests");
            }
        }
        Ok(matched)
    }
}

#[derive(Default)]
pub struct Decisions {
    pub matched: usize,
    pub granted: usize,
    pub denied: usize,
}

// Deliberately no Debug/Display: these values must never enter assertion output.
pub struct Controller {
    port: u16,
    credentials: Vec<String>,
    fixture: Fixture,
    used: BTreeSet<usize>,
    pub decisions: Decisions,
}

impl Controller {
    pub fn attach(home: &ThrowawayHome, port: u16, fixture: Fixture) -> Result<Self> {
        home.guard(home.home(), home.data())?;
        let path = home.data().join("runtime-coords.json");
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "fixture coordinates file is missing")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 {
            return Err("fixture coordinates must be a small regular file");
        }
        let bytes = fs::read(path).map_err(|_| "could not read fixture coordinates")?;
        let secret = attach_secret(&bytes)?;
        let token = shell_attach(port, &secret)?;
        Ok(Self {
            port,
            credentials: vec![secret, token],
            fixture,
            used: BTreeSet::new(),
            decisions: Decisions::default(),
        })
    }

    fn call(&self, method: &str, path: &str, body: &Value) -> Result<Value> {
        http(self.port, method, path, Some(&self.credentials[1]), body)
    }

    /// Seed through the production Runtime provider route. Runtime owns the
    /// stored representation; the guest later reads it using its own grant.
    pub fn seed_read_files(&self) -> Result<()> {
        for name in ["granted.txt", "sibling.txt"] {
            let response = self.call(
                "POST",
                "/api/provider/localhost/write",
                &json!({
                    "path": format!("localhost://Public/agent-conformance-grants/{name}"),
                    "content": include_bytes!("../../fixtures/granted-bytes.txt").as_slice(),
                    "append": false
                }),
            )?;
            if response["status"] != "ok" {
                return Err("Runtime could not seed the fixture file");
            }
        }
        Ok(())
    }

    pub fn poll(&mut self) -> Result<()> {
        let response = self.call("GET", "/api/capability/pending", &Value::Null)?;
        let pending = response["requests"]
            .as_array()
            .ok_or("pending response requires a request list")?;
        let mut ids = BTreeSet::new();
        for request in pending {
            if !ids.insert(field(request, "request_id")?) {
                return Err("pending response repeats a request id");
            }
            field(request, "session_id")?;
        }
        let decisions = match self.fixture.decisions(pending, &self.used) {
            Ok(decisions) => decisions,
            Err(reason) => {
                // Refuse the entire snapshot; never choose one ambiguous match.
                for request in pending {
                    self.deny(request, reason)?;
                }
                return Err(reason);
            }
        };
        for (request, decision) in pending.iter().zip(decisions) {
            if let Some(index) = decision {
                self.decisions.matched += 1;
                let response = self.call(
                    "POST",
                    "/api/capability/grant",
                    &json!({
                        "request_id": field(request, "request_id")?,
                        "duration": self.fixture.entries[index]["duration"],
                        "rationale": "isolated conformance fixture"
                    }),
                )?;
                require_success(&response)?;
                self.credentials.push(field(&response, "token")?.to_owned());
                self.used.insert(index);
                self.decisions.granted += 1;
                println!("fixture controller: matched, granted");
            } else {
                let reason = self.fixture.deny_reason.clone();
                self.deny(request, &reason)?;
            }
        }
        Ok(())
    }

    fn deny(&mut self, request: &Value, reason: &str) -> Result<()> {
        let response = self.call(
            "POST",
            "/api/capability/deny",
            &json!({
                "request_id": field(request, "request_id")?, "reason": reason
            }),
        )?;
        require_success(&response)?;
        self.decisions.denied += 1;
        println!("fixture controller: denied");
        Ok(())
    }

    pub fn deny_reason(&self) -> &str {
        &self.fixture.deny_reason
    }

    pub fn check_captures(&self, home: &ThrowawayHome) -> Result<()> {
        home.guard(home.home(), home.data())?;
        // Inspect only harness-owned output files; Runtime state and keys stay
        // under Runtime ownership. Refuse symlinks before reading a capture.
        for entry in fs::read_dir(home.root()).map_err(|_| "could not inspect captures")? {
            let entry = entry.map_err(|_| "could not inspect capture entry")?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("stdout-") || name.starts_with("stderr-") {
                if !entry
                    .file_type()
                    .map_err(|_| "could not inspect capture type")?
                    .is_file()
                {
                    return Err("capture must be a regular file");
                }
                let bytes = fs::read(entry.path()).map_err(|_| "could not read capture")?;
                self.check_bytes(&bytes)?;
            }
        }
        Ok(())
    }

    fn check_bytes(&self, bytes: &[u8]) -> Result<()> {
        if self.credentials.iter().any(|value| {
            bytes
                .windows(value.len())
                .any(|part| part == value.as_bytes())
        }) {
            return Err("fixture credential appeared in a capture");
        }
        Ok(())
    }
}

fn attach_secret(bytes: &[u8]) -> Result<String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "invalid fixture coordinates JSON")?;
    field(&value, "attach_secret")
        .map(str::to_owned)
        .map_err(|_| "fixture coordinates require attach_secret")
}

fn shell_attach(port: u16, secret: &str) -> Result<String> {
    let response = http(
        port,
        "POST",
        "/api/auth/attach",
        None,
        &json!({"secret": secret, "scope": "shell"}),
    )
    .map_err(|_| "fixture shell attach failed")?;
    let token = field(&response, "token").map_err(|_| "fixture shell attach returned no token")?;
    if !header_token(token) {
        return Err("fixture shell attach returned an invalid token");
    }
    Ok(token.to_owned())
}

fn require_success(value: &Value) -> Result<()> {
    if value["success"] != true {
        return Err("fixture approval route refused the decision");
    }
    Ok(())
}

fn header_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Only a port is accepted; neither coordinates nor HTTP responses can select
/// a host or redirect. Bounded HTTP/1.1 with Content-Length is what Axum serves.
fn http(port: u16, method: &str, path: &str, token: Option<&str>, body: &Value) -> Result<Value> {
    let bound = Duration::from_secs(2);
    let started = Instant::now();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, bound).map_err(|_| "fixture loopback connect failed")?;
    stream
        .set_write_timeout(Some(bound))
        .map_err(|_| "could not bound fixture write")?;
    let body = if body.is_null() {
        Vec::new()
    } else {
        serde_json::to_vec(body).map_err(|_| "could not encode fixture request")?
    };
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
    if let Some(token) = token {
        if !header_token(token) {
            return Err("invalid fixture authorization header");
        }
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|_| stream.write_all(&body))
        .map_err(|_| "fixture request write failed")?;
    let mut bytes = Vec::new();
    loop {
        let remaining = bound
            .checked_sub(started.elapsed())
            .filter(|d| !d.is_zero())
            .ok_or("fixture HTTP response exceeded its bound")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| "could not bound fixture read")?;
        let mut chunk = [0; 4096];
        let size = stream
            .read(&mut chunk)
            .map_err(|_| "fixture response read failed")?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > 1024 * 1024 {
            return Err("fixture HTTP response exceeded size bound");
        }
    }
    response_json(&bytes)
}

fn response_json(bytes: &[u8]) -> Result<Value> {
    let split = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or("fixture response lacks HTTP headers")?;
    let head =
        std::str::from_utf8(&bytes[..split]).map_err(|_| "invalid fixture response headers")?;
    let mut lines = head.split("\r\n");
    if !lines
        .next()
        .is_some_and(|line| line.starts_with("HTTP/1.1 200 "))
    {
        return Err("fixture HTTP request was refused");
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("invalid fixture response header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("unsupported fixture response encoding");
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err("repeated fixture response length");
            }
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid fixture response length")?,
            );
        }
    }
    let body = &bytes[split + 4..];
    if length != Some(body.len()) {
        return Err("fixture response length mismatch");
    }
    serde_json::from_slice(body).map_err(|_| "invalid fixture response JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Fixture {
        Fixture::parse(r#"{"deny_reason":"fixture denial","grants":[{"resource":"localhost://Public/test/one","action":"read","reason":"test read","duration":"once"}]}"#).unwrap()
    }

    fn request() -> Value {
        json!({"resource":"localhost://Public/test/one","action":"read","reason":"test read"})
    }

    #[test]
    fn controller_matches_all_fields_exactly() {
        let fixture = fixture();
        assert_eq!(fixture.matches(&request()), Ok(Some(0)));
        for (field, value) in [
            ("resource", "localhost://Public/test/one/sibling"),
            ("action", "write"),
            ("reason", "another test"),
        ] {
            let mut changed = request();
            changed[field] = json!(value);
            assert_eq!(fixture.matches(&changed), Ok(None));
        }
    }

    #[test]
    fn controller_refuses_ambiguous_requests_before_deciding() {
        let fixture = fixture();
        let reason = "ambiguous fixture grant: an entry matches multiple requests";
        assert_eq!(
            fixture.decisions(&[request(), request()], &BTreeSet::new()),
            Err(reason)
        );
        assert_eq!(
            fixture.decisions(&[request()], &BTreeSet::from([0])),
            Err(reason)
        );
    }

    #[test]
    fn controller_requires_explicit_fixture_and_credentials() {
        for text in ["{}", r#"{"deny_reason":"denied","grants":[{}]}"#] {
            assert!(Fixture::parse(text).is_err());
        }
        for bytes in [
            b"{}".as_slice(),
            br#"{"attach_secret":""}"#,
            br#"{"attach_secret":42}"#,
            b"invalid",
        ] {
            assert!(attach_secret(bytes).is_err());
        }
        let home = ThrowawayHome::new().unwrap();
        assert!(matches!(
            Controller::attach(&home, 1, fixture()),
            Err("fixture coordinates file is missing")
        ));
        fs::write(home.data().join("runtime-coords.json"), b"{}").unwrap();
        assert!(matches!(
            Controller::attach(&home, 1, fixture()),
            Err("fixture coordinates require attach_secret")
        ));
        home.finish().unwrap();
    }

    #[test]
    fn controller_refuses_failed_attach_and_http_responses() {
        // Port zero cannot be an API listener. Only a synthetic in-memory value
        // is supplied, and the refusal never includes the response or credential.
        assert!(matches!(
            shell_attach(0, "fixture-canary"),
            Err("fixture shell attach failed")
        ));
        assert!(response_json(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").is_ok());
        for bytes in [
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 302 Found\r\nLocation: https://example.invalid\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ] {
            assert!(response_json(bytes).is_err());
        }
        assert!(require_success(&json!({"success":false})).is_err());
        assert!(require_success(&json!({})).is_err());
    }

    #[test]
    fn controller_detects_credentials_without_disclosing_them() {
        // Synthetic canaries exist only in memory, even when testing detection.
        let controller = Controller {
            port: 1,
            credentials: vec!["fixture-canary".into()],
            fixture: fixture(),
            used: BTreeSet::new(),
            decisions: Decisions::default(),
        };
        assert!(controller.check_bytes(b"ordinary output").is_ok());
        assert!(controller
            .check_bytes(b"prefix fixture-canary suffix")
            .is_err());
        assert!(!header_token("fixture\r\nheader"));
    }
}
