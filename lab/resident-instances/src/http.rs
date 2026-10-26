//! The operator adapter: the journeys' calls as shell requests on the routes
//! SPEC.md names. It reaches only IPv4 loopback, keeps the attach secret and
//! session token in memory, and bounds every response.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::capability::Check;
use crate::contract::{
    Actor, Fixture, Instance, LiveGrant, Request, RequestRecord, ResidentRuntime, State, Status,
};

pub const COORDS_VAR: &str = "RESIDENT_RUNTIME_COORDS";
pub const READ_SHARED_VAR: &str = "RESIDENT_FIXTURE_READ_SHARED";
pub const FAIL_AFTER_SUBMIT_VAR: &str = "RESIDENT_FIXTURE_FAIL_AFTER_SUBMIT";

const HTTP_BOUND: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 1024 * 1024;
const PAUSE: Duration = Duration::from_millis(50);

/// What a live run needs from the person running it: the operator's
/// coordinates file and the built fixture capsule directories.
pub struct Setup {
    coords: PathBuf,
    read_shared: Option<PathBuf>,
    fail_after_submit: Option<PathBuf>,
}

fn fixture_var(fixture: Fixture) -> &'static str {
    match fixture {
        Fixture::ReadShared => READ_SHARED_VAR,
        Fixture::FailAfterSubmit => FAIL_AFTER_SUBMIT_VAR,
    }
}

impl Setup {
    pub fn from_env(check: Check) -> Result<Setup, String> {
        Setup::from_lookup(check, |name| std::env::var_os(name).map(PathBuf::from))
    }

    pub fn from_lookup(
        check: Check,
        lookup: impl Fn(&str) -> Option<PathBuf>,
    ) -> Result<Setup, String> {
        let path = |name: &str| -> Result<PathBuf, String> {
            let value = lookup(name).ok_or(format!("{name} is not set"))?;
            if !value.is_absolute() {
                return Err(format!("{name} must be an absolute path"));
            }
            Ok(value)
        };
        let coords = path(COORDS_VAR)?;
        if !coords.is_file() {
            return Err(format!("{COORDS_VAR} names no file"));
        }
        let mut setup = Setup {
            coords,
            read_shared: None,
            fail_after_submit: None,
        };
        for fixture in check.fixtures() {
            let var = fixture_var(*fixture);
            let dir = path(var)?;
            if !dir.join("capsule.json").is_file() {
                return Err(format!(
                    "{var} names no capsule directory with capsule.json"
                ));
            }
            match fixture {
                Fixture::ReadShared => setup.read_shared = Some(dir),
                Fixture::FailAfterSubmit => setup.fail_after_submit = Some(dir),
            }
        }
        Ok(setup)
    }
}

/// The parts of the Runtime's coordinates file the adapter uses.
pub struct Coords {
    pub port: u16,
    pub pid: u32,
    secret: String,
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or(format!("missing string field {field}"))
}

fn optional_text(value: &Value, field: &str) -> Result<String, String> {
    match &value[field] {
        Value::Null => Ok(String::new()),
        Value::String(text) => Ok(text.clone()),
        _ => Err(format!("field {field} is not a string")),
    }
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
    let pid = value["pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid > 1)
        .ok_or("the coordinates name no Runtime pid")?;
    let secret = text(&value, "attach_secret")?.to_owned();
    if secret.is_empty() {
        return Err("the coordinates hold an empty attach secret".to_owned());
    }
    Ok(Coords { port, pid, secret })
}

fn header_safe(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Instance ids and sessions go into paths and queries unescaped.
pub fn segment_safe(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':'))
        && text != "."
        && text != ".."
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

/// One bounded HTTP/1.1 exchange with the operator on IPv4 loopback. Only a
/// port is accepted, so neither coordinates nor responses can pick a host.
fn http(
    port: u16,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(u16, Vec<u8>), String> {
    let started = Instant::now();
    let fail = |what: &str| format!("{method} {path}: {what}");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut stream = TcpStream::connect_timeout(&addr, HTTP_BOUND)
        .map_err(|_| fail("loopback connect failed"))?;
    stream
        .set_write_timeout(Some(HTTP_BOUND))
        .map_err(|_| fail("cannot bound the write"))?;
    let body = match body {
        Some(body) => serde_json::to_vec(body).map_err(|_| fail("cannot encode the body"))?,
        None => Vec::new(),
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        head.push_str("Content-Type: application/json\r\n");
    }
    if let Some(token) = token {
        if !header_safe(token) {
            return Err(fail("the session token cannot be sent as a header"));
        }
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .map_err(|_| fail("the request write failed"))?;
    let mut bytes = Vec::new();
    loop {
        let remaining = HTTP_BOUND
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| fail("the response exceeded its time bound"))?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| fail("cannot bound the read"))?;
        let mut chunk = [0; 4096];
        let size = stream
            .read(&mut chunk)
            .map_err(|_| fail("the response read failed"))?;
        if size == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..size]);
        if bytes.len() > MAX_RESPONSE {
            return Err(fail("the response exceeded its size bound"));
        }
    }
    parse_response(&bytes).map_err(|reason| fail(&reason))
}

fn parse_json(bytes: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(bytes).map_err(|_| "the response body is not JSON".to_owned())
}

pub fn parse_instance(value: &Value) -> Result<Instance, String> {
    Ok(Instance {
        id: text(value, "id")?.to_owned(),
        session: text(value, "session_id")?.to_owned(),
        state: State::parse(text(value, "status")?),
        cause: optional_text(value, "cause")?,
    })
}

/// `GET /api/capsules`. Entries of other capsule kinds carry no session; they
/// parse with an empty one and never match a launched instance.
pub fn parse_instances(value: &Value) -> Result<Vec<Instance>, String> {
    value["capsules"]
        .as_array()
        .ok_or("GET /api/capsules returned no capsules list")?
        .iter()
        .map(|entry| {
            Ok(Instance {
                id: text(entry, "id")?.to_owned(),
                session: optional_text(entry, "session_id")?,
                state: State::parse(text(entry, "status")?),
                cause: optional_text(entry, "cause")?,
            })
        })
        .collect()
}

fn parse_request(value: &Value) -> Result<Request, String> {
    Ok(Request {
        id: text(value, "request_id")?.to_owned(),
        session: text(value, "session_id")?.to_owned(),
        resource: text(value, "resource")?.to_owned(),
        action: text(value, "action")?.to_owned(),
        reason: text(value, "reason")?.to_owned(),
    })
}

pub fn parse_pending(value: &Value) -> Result<Vec<Request>, String> {
    value["requests"]
        .as_array()
        .ok_or("GET /api/capability/pending returned no requests list")?
        .iter()
        .map(parse_request)
        .collect()
}

/// `GET /api/capability/requests?session=` (RI-5). A pending record has no
/// settler; every decided record names one.
pub fn parse_records(value: &Value) -> Result<Vec<RequestRecord>, String> {
    value["requests"]
        .as_array()
        .ok_or("GET /api/capability/requests returned no requests list (RI-5)")?
        .iter()
        .map(|entry| {
            let status = match text(entry, "status")? {
                "pending" => Status::Pending,
                "granted" => Status::Granted,
                "denied" => Status::Denied,
                "expired" => Status::Expired,
                other => return Err(format!("unknown request status {other:?}")),
            };
            let settled_by = match &entry["settled_by"] {
                Value::Null => None,
                Value::String(actor) if actor == "shell" => Some(Actor::Shell),
                Value::String(actor) if actor == "runtime" => Some(Actor::Runtime),
                other => return Err(format!("unknown settled_by {other}")),
            };
            if (status == Status::Pending) != settled_by.is_none() {
                return Err(format!(
                    "a {status:?} record must {} settled_by",
                    if status == Status::Pending {
                        "omit"
                    } else {
                        "name"
                    }
                ));
            }
            Ok(RequestRecord {
                request: parse_request(entry)?,
                status,
                decision: optional_text(entry, "decision_reason")?,
                settled_by,
            })
        })
        .collect()
}

/// `GET /api/capability/list?scope=all_sessions_live` (RI-7). A response
/// without the global scope is the caller's own session view and is refused.
pub fn parse_live_grants(value: &Value) -> Result<Vec<LiveGrant>, String> {
    if value["scope"] != "all_sessions_live" {
        return Err(
            "GET /api/capability/list did not return the all_sessions_live view (RI-7)".to_owned(),
        );
    }
    value["capabilities"]
        .as_array()
        .ok_or("the live-grant view has no capabilities list")?
        .iter()
        .map(|entry| {
            Ok(LiveGrant {
                request_id: text(entry, "request_id")?.to_owned(),
                session: text(entry, "session_id")?.to_owned(),
                resource: text(entry, "resource")?.to_owned(),
                action: text(entry, "action")?.to_owned(),
            })
        })
        .collect()
}

/// Every process below `root` in a `ps -A -o pid=,ppid=` table.
pub fn descendants(table: &str, root: u32) -> Result<Vec<u32>, String> {
    let mut pairs = Vec::new();
    for line in table.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let pid = fields.next().and_then(|f| f.parse::<u32>().ok());
        let parent = fields.next().and_then(|f| f.parse::<u32>().ok());
        match (pid, parent, fields.next()) {
            (Some(pid), Some(parent), None) => pairs.push((pid, parent)),
            _ => return Err(format!("unreadable process line {line:?}")),
        }
    }
    if !pairs.iter().any(|(pid, _)| *pid == root) {
        return Err("the Runtime process is not running".to_owned());
    }
    let mut found = Vec::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (pid, of) in &pairs {
            if *of == parent && *pid != root && !found.contains(pid) {
                found.push(*pid);
                frontier.push(*pid);
            }
        }
    }
    found.sort_unstable();
    Ok(found)
}

pub struct OperatorRuntime {
    port: u16,
    pid: u32,
    token: String,
    read_shared: Option<PathBuf>,
    fail_after_submit: Option<PathBuf>,
    started: Instant,
}

impl OperatorRuntime {
    pub fn attach(setup: &Setup) -> Result<Self, String> {
        let bytes = std::fs::read(&setup.coords)
            .map_err(|e| format!("cannot read the coordinates: {e}"))?;
        let coords = parse_coords(&bytes)?;
        let attach = json!({"secret": coords.secret, "scope": "shell"});
        let (status, body) = http(coords.port, "POST", "/api/auth/attach", None, Some(&attach))?;
        if status != 200 {
            return Err(format!("POST /api/auth/attach returned HTTP {status}"));
        }
        let value = parse_json(&body)?;
        if value["session_type"] != "shell" {
            return Err("the attach did not open a shell session".to_owned());
        }
        let token = text(&value, "token")?.to_owned();
        if !header_safe(&token) {
            return Err("the attach token cannot be sent as a header".to_owned());
        }
        Ok(Self {
            port: coords.port,
            pid: coords.pid,
            token,
            read_shared: setup.read_shared.clone(),
            fail_after_submit: setup.fail_after_submit.clone(),
            started: Instant::now(),
        })
    }

    fn exchange(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Vec<u8>, String> {
        let (status, bytes) = http(self.port, method, path, Some(&self.token), body)?;
        if status != 200 {
            return Err(format!("{method} {path} returned HTTP {status}"));
        }
        Ok(bytes)
    }

    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        parse_json(&self.exchange(method, path, body)?)
            .map_err(|reason| format!("{method} {path}: {reason}"))
    }

    fn decided(&self, path: &str, body: Value) -> Result<(), String> {
        if self.call("POST", path, Some(&body))?["success"] != true {
            return Err(format!("POST {path} refused the decision"));
        }
        Ok(())
    }
}

impl ResidentRuntime for OperatorRuntime {
    fn launch(&mut self, fixture: Fixture) -> Result<Instance, String> {
        let dir = match fixture {
            Fixture::ReadShared => &self.read_shared,
            Fixture::FailAfterSubmit => &self.fail_after_submit,
        }
        .as_ref()
        .ok_or(format!(
            "no capsule directory for fixture {}",
            fixture.name()
        ))?;
        let path = dir.to_str().ok_or("the fixture path is not UTF-8")?;
        let value = self.call("POST", "/api/capsules", Some(&json!({"path": path})))?;
        parse_instance(&value).map_err(|reason| format!("POST /api/capsules: {reason} (RI-2)"))
    }

    fn instances(&mut self) -> Result<Vec<Instance>, String> {
        parse_instances(&self.call("GET", "/api/capsules", None)?)
    }

    fn stop(&mut self, id: &str, reason: &str) -> Result<(), String> {
        if !segment_safe(id) {
            return Err("the instance id is not path-safe".to_owned());
        }
        self.exchange(
            "DELETE",
            &format!("/api/capsules/{id}"),
            Some(&json!({"reason": reason})),
        )
        .map(drop)
    }

    fn pending(&mut self) -> Result<Vec<Request>, String> {
        parse_pending(&self.call("GET", "/api/capability/pending", None)?)
    }

    fn requests(&mut self, session: &str) -> Result<Vec<RequestRecord>, String> {
        if !segment_safe(session) {
            return Err("the session is not query-safe".to_owned());
        }
        parse_records(&self.call(
            "GET",
            &format!("/api/capability/requests?session={session}"),
            None,
        )?)
    }

    fn grant_session(&mut self, request_id: &str) -> Result<(), String> {
        self.decided(
            "/api/capability/grant",
            json!({"request_id": request_id, "duration": "session"}),
        )
    }

    fn deny(&mut self, request_id: &str, reason: &str) -> Result<(), String> {
        self.decided(
            "/api/capability/deny",
            json!({"request_id": request_id, "reason": reason}),
        )
    }

    fn live_grants(&mut self) -> Result<Vec<LiveGrant>, String> {
        parse_live_grants(&self.call(
            "GET",
            "/api/capability/list?scope=all_sessions_live",
            None,
        )?)
    }

    fn seed(&mut self, resource: &str, bytes: &[u8]) -> Result<(), String> {
        let content = std::str::from_utf8(bytes).map_err(|_| "seed bytes must be UTF-8")?;
        let body = json!({"path": resource, "content": content, "append": false});
        if self.call("POST", "/api/provider/localhost/write", Some(&body))?["status"] != "ok" {
            return Err("the Runtime did not write the seed".to_owned());
        }
        Ok(())
    }

    fn processes(&mut self) -> Result<Vec<u32>, String> {
        let output = Command::new("ps")
            .args(["-A", "-o", "pid=,ppid="])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run ps: {e}"))?;
        if !output.status.success() {
            return Err(format!("ps exited with {}", output.status));
        }
        let table = String::from_utf8(output.stdout).map_err(|_| "ps output is not UTF-8")?;
        descendants(&table, self.pid)
    }

    fn healthy(&mut self) -> Result<(), String> {
        if self.call("GET", "/api/health", None)?["status"] != "ok" {
            return Err("GET /api/health did not report ok".to_owned());
        }
        Ok(())
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    fn pause(&mut self) {
        std::thread::sleep(PAUSE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn coords(edit: impl FnOnce(&mut Value)) -> Result<Coords, String> {
        let mut value = json!({
            "api_url": "http://127.0.0.1:48123",
            "attach_secret": "synthetic-secret",
            "pid": 4242,
            "runtime_kind": "operator"
        });
        edit(&mut value);
        parse_coords(value.to_string().as_bytes())
    }

    #[test]
    fn coordinates_name_only_a_loopback_operator() {
        let good = coords(|_| {}).unwrap();
        assert_eq!((good.port, good.pid), (48123, 4242));
        for (field, value) in [
            ("api_url", json!("https://127.0.0.1:48123")),
            ("api_url", json!("http://localhost:48123")),
            ("api_url", json!("http://0.0.0.0:48123")),
            ("api_url", json!("http://127.0.0.1:0")),
            ("runtime_kind", json!("gateway")),
            ("attach_secret", json!("")),
            ("pid", json!(1)),
            ("pid", Value::Null),
        ] {
            assert!(
                coords(|v| v[field] = value.clone()).is_err(),
                "{field} = {value} must be refused"
            );
        }
    }

    #[test]
    fn responses_need_one_exact_length_and_no_chunking() {
        let ok = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
        assert_eq!(parse_response(ok).unwrap(), (200, b"{}".to_vec()));
        let missing = b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n";
        assert_eq!(parse_response(missing).unwrap().0, 404);
        for bad in [
            &b"HTTP/1.1 200 OK\r\n\r\n{}"[..],
            b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ncontent-length: 2\r\n\r\n{}",
            b"HTTP/1.0 200 OK\r\ncontent-length: 2\r\n\r\n{}",
            b"no headers",
        ] {
            assert!(
                parse_response(bad).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_launch_must_name_its_bus_session() {
        let live = json!({"id": "i-1", "name": "f", "status": "starting", "session_id": "s-1"});
        let parsed = parse_instance(&live).unwrap();
        assert_eq!((parsed.state, parsed.cause.as_str()), (State::Starting, ""));
        let today = json!({"id": "component-1", "name": "f", "status": "completed"});
        assert!(
            parse_instance(&today).is_err(),
            "today's launch answer has no session"
        );
    }

    #[test]
    fn the_instance_list_keeps_status_session_and_cause() {
        let list = json!({"capsules": [
            {"id": "i-1", "name": "f", "status": "stopped", "session_id": "s-1", "cause": "stopped: reason"},
            {"id": "vm-1", "name": "browser", "status": "launched"}
        ]});
        let parsed = parse_instances(&list).unwrap();
        assert_eq!(parsed[0].state, State::Stopped);
        assert_eq!(parsed[0].cause, "stopped: reason");
        assert_eq!(parsed[1].session, "");
        assert_eq!(parsed[1].state, State::Other("launched".to_owned()));
        assert!(!parsed[1].state.live());
        assert!(parse_instances(&json!({"capsules": [{"id": "x", "status": 3}]})).is_err());
    }

    #[test]
    fn a_settlement_record_is_consistent_about_its_settler() {
        let record = |status: &str, settled_by: Value| {
            json!({"requests": [{
                "request_id": "r-1", "session_id": "s-1", "resource": "localhost://Public/x",
                "action": "read", "reason": "why", "status": status,
                "decision_reason": "instance stopped: x", "settled_by": settled_by
            }]})
        };
        let parsed = parse_records(&record("denied", json!("runtime"))).unwrap();
        assert_eq!(parsed[0].status, Status::Denied);
        assert_eq!(parsed[0].settled_by, Some(Actor::Runtime));
        assert_eq!(parsed[0].decision, "instance stopped: x");
        assert!(parse_records(&record("pending", Value::Null)).is_ok());
        for (status, settled_by) in [
            ("pending", json!("runtime")),
            ("denied", Value::Null),
            ("denied", json!("home")),
            ("cancelled", json!("runtime")),
        ] {
            assert!(
                parse_records(&record(status, settled_by.clone())).is_err(),
                "{status} / {settled_by}"
            );
        }
    }

    #[test]
    fn live_grants_need_the_global_scope() {
        let today = json!({"capabilities": []});
        assert!(parse_live_grants(&today).unwrap_err().contains("RI-7"));
        let local = json!({"scope": "session", "capabilities": []});
        assert!(parse_live_grants(&local).is_err());
        let global = json!({"scope": "all_sessions_live", "capabilities": [
            {"request_id": "r", "session_id": "s", "resource": "localhost://Public/x", "action": "read", "duration": "session"}
        ]});
        assert_eq!(parse_live_grants(&global).unwrap()[0].session, "s");
    }

    #[test]
    fn the_process_census_walks_only_below_the_runtime() {
        let table = "  1     0\n 10     1\n 11    10\n 12    11\n 20     1\n 21    20\n";
        assert_eq!(descendants(table, 10).unwrap(), [11, 12]);
        assert_eq!(descendants(table, 12).unwrap(), Vec::<u32>::new());
        assert!(
            descendants(table, 99).is_err(),
            "a missing Runtime is refused"
        );
        assert!(descendants("10 1 extra\n", 10).is_err());
        assert!(descendants("ten 1\n", 10).is_err());
    }

    #[test]
    fn ids_must_be_path_and_query_safe() {
        for good in ["component-0f1e", "i_1", "person:local:ab12", "a.b"] {
            assert!(segment_safe(good), "{good}");
        }
        for bad in ["", ".", "..", "../x", "a/b", "a b", "a?b", "a&b", "a%2F"] {
            assert!(!segment_safe(bad), "{bad}");
        }
        assert!(!segment_safe(&"a".repeat(129)));
    }

    #[test]
    fn setup_names_the_first_missing_item() {
        let lane = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let coords_file = lane.join("Cargo.toml");
        let fixture_dir = lane.join("target");
        let none = |_: &str| None;
        assert_eq!(
            Setup::from_lookup(Check::A3, none).err().unwrap(),
            "RESIDENT_RUNTIME_COORDS is not set"
        );
        let relative = |_: &str| Some(PathBuf::from("coords.json"));
        assert!(Setup::from_lookup(Check::A3, relative)
            .err()
            .unwrap()
            .contains("absolute"));
        let only_coords = |name: &str| (name == COORDS_VAR).then(|| coords_file.clone());
        assert_eq!(
            Setup::from_lookup(Check::A3, only_coords).err().unwrap(),
            "RESIDENT_FIXTURE_READ_SHARED is not set"
        );
        let no_manifest = |name: &str| {
            Some(if name == COORDS_VAR {
                coords_file.clone()
            } else {
                fixture_dir.clone()
            })
        };
        assert!(Setup::from_lookup(Check::A11, no_manifest)
            .err()
            .unwrap()
            .contains("RESIDENT_FIXTURE_FAIL_AFTER_SUBMIT names no capsule directory"));
    }
}
