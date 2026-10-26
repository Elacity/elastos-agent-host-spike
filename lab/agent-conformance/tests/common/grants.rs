//! The fixture's one shell approver. Credentials and HTTP bodies stay in memory.

use agent_conformance::build::repository;
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::Observation;
use agent_conformance::report::{render_run, GitIdentity};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Component, Path};
use std::process::Command;
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
    /// Missing policy supplies zero entries. The caller leaves requests pending
    /// so the Runtime's own default is observed, without a controller denial.
    pub fn no_policy() -> Result<(Self, bool)> {
        let path = repository().join("lab/agent-conformance/fixtures/no-policy.json");
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((
                Self {
                    deny_reason: "fixture policy absent".into(),
                    entries: Vec::new(),
                },
                false,
            )),
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 65536 =>
            {
                let text = fs::read_to_string(path).map_err(|_| "could not read fixture policy")?;
                Ok((Self::parse(&text)?, true))
            }
            _ => Err("fixture policy must be a small regular file"),
        }
    }

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
    printed: RefCell<String>,
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
            printed: RefCell::default(),
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
                self.print_checked("fixture controller: matched, granted")?;
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
        self.print_checked("fixture controller: denied")?;
        Ok(())
    }

    /// Shell pending is global. The current grant list is session-local, so
    /// it supplies zero proof about a collected run client's live grants.
    pub fn cleanup_state(&self) -> Result<&'static str> {
        let pending = self.call("GET", "/api/capability/pending", &Value::Null)?;
        require_empty_pending(&pending)?;
        let grants = self.call("GET", "/api/capability/list", &Value::Null)?;
        live_grant_state(&grants)
    }

    pub fn print_checked(&self, line: &str) -> Result<()> {
        self.check_bytes(line.as_bytes(), Surface::Printed)?;
        self.printed.borrow_mut().push_str(&format!("{line}\n"));
        println!("{line}");
        Ok(())
    }

    pub fn deny_reason(&self) -> &str {
        &self.fixture.deny_reason
    }

    pub fn check_captures(&self, home: &ThrowawayHome) -> Result<()> {
        // The spawn site owns this inventory, including every helper command.
        // Require every expected pair after group drain; scan zero Runtime files.
        for pair in home.capture_paths()? {
            for (path, surface) in pair.iter().zip([Surface::Stdout, Surface::Stderr]) {
                let metadata =
                    fs::symlink_metadata(path).map_err(|_| "expected capture is missing")?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err("capture must be a regular file");
                }
                let bytes = fs::read(path).map_err(|_| "could not read capture")?;
                self.check_bytes(&bytes, surface)?;
            }
        }
        Ok(())
    }

    pub fn check_sources(&self) -> Result<()> {
        self.check_inventory(
            &source_inventory()?,
            &[Surface::Committed, Surface::Candidate],
        )
    }

    pub fn check_report(&self, name: &str, observations: &[Observation]) -> Result<()> {
        self.check_journey(name, observations, true)
    }

    pub fn check_journey(
        &self,
        name: &str,
        observations: &[Observation],
        passed: bool,
    ) -> Result<()> {
        // Use the exact lines printed by this controller, including decisions
        // made before a grant token arrived. Recheck with all credentials known.
        let printed = self.printed.borrow();
        self.check_inventory(
            &report_inventory(name, observations, &printed, passed)?,
            &[Surface::Printed, Surface::Report, Surface::Receipt],
        )
    }

    fn check_inventory(
        &self,
        inventory: &[(Surface, Vec<u8>)],
        required: &[Surface],
    ) -> Result<()> {
        for surface in required {
            if !inventory
                .iter()
                .any(|(label, bytes)| label == surface && !bytes.is_empty())
            {
                return Err("required source or report inventory is empty");
            }
        }
        for (surface, bytes) in inventory {
            self.check_bytes(bytes, *surface)?;
        }
        Ok(())
    }

    fn check_bytes(&self, bytes: &[u8], surface: Surface) -> Result<()> {
        if self.credentials.iter().any(|value| {
            bytes
                .windows(value.len())
                .any(|part| part == value.as_bytes())
        }) {
            return Err(surface.refusal());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Surface {
    Stdout,
    Stderr,
    Report,
    Receipt,
    Printed,
    Committed,
    Candidate,
}

impl Surface {
    fn refusal(self) -> &'static str {
        match self {
            Self::Stdout => "fixture credential detected: child stdout",
            Self::Stderr => "fixture credential detected: child stderr",
            Self::Report => "fixture credential detected: report",
            Self::Receipt => "fixture credential detected: version receipt",
            Self::Printed => "fixture credential detected: printed journey",
            Self::Committed => "fixture credential detected: committed lane source",
            Self::Candidate => "fixture credential detected: candidate lane source",
        }
    }
}

// Git lists only this lane's source files. Blob and candidate bytes remain in
// memory. Ignored builds, Homes and Runtime coordinates stay outside this list.
fn git(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(repository())
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args(args)
        .output()
        .map_err(|_| "lane source inventory command failed")?;
    if !output.status.success() {
        return Err("lane source inventory command failed");
    }
    Ok(output.stdout)
}

fn source_path(path: &str) -> Result<&Path> {
    let path = Path::new(path);
    if !path.starts_with("lab/agent-conformance")
        || path.components().count() < 3
        || !path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err("source inventory escaped the lane");
    }
    Ok(path)
}

fn source_inventory() -> Result<Vec<(Surface, Vec<u8>)>> {
    let mut inventory = Vec::new();
    let tree = git(&["ls-tree", "-rz", "HEAD", "--", "lab/agent-conformance/"])?;
    let tree = std::str::from_utf8(&tree).map_err(|_| "lane source inventory is not UTF-8")?;
    for entry in tree.split('\0').filter(|entry| !entry.is_empty()) {
        let (fields, path) = entry
            .split_once('\t')
            .ok_or("invalid lane source inventory")?;
        source_path(path)?;
        let fields: Vec<_> = fields.split_whitespace().collect();
        if fields.len() != 3 || !matches!(fields[0], "100644" | "100755") || fields[1] != "blob" {
            return Err("committed lane source must be a regular blob");
        }
        inventory.push((Surface::Committed, git(&["cat-file", "blob", fields[2]])?));
    }
    let candidates = git(&[
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
        "--",
        "lab/agent-conformance/",
    ])?;
    let candidates =
        std::str::from_utf8(&candidates).map_err(|_| "lane source inventory is not UTF-8")?;
    for name in candidates.split('\0').filter(|name| !name.is_empty()) {
        let relative = source_path(name)?;
        let mut path = repository();
        let mut missing = false;
        for part in relative.components() {
            path.push(part);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err("candidate source must exclude symlinks")
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing = true;
                    break;
                }
                Err(_) => return Err("could not inspect candidate source"),
            }
        }
        if missing {
            continue;
        } // Deleted candidates remain covered by their committed blobs.
        if !path.is_file() {
            return Err("candidate source must be a regular file");
        }
        inventory.push((
            Surface::Candidate,
            fs::read(path).map_err(|_| "could not read candidate source")?,
        ));
    }
    Ok(inventory)
}

fn report_inventory(
    name: &str,
    observations: &[Observation],
    printed: &str,
    passed: bool,
) -> Result<Vec<(Surface, Vec<u8>)>> {
    let listed = format!("{name}: test\n");
    let result = if passed { "ok" } else { "FAILED" };
    let mut output = format!("{printed}test {name} ... {result}\n");
    for observation in observations {
        output.push_str(&observation.line());
        output.push('\n');
    }
    let report = render_run(&listed, &output, passed, GitIdentity::read(&repository()));
    if !report.failures.is_empty() {
        return Err("credential check requires a complete report");
    }
    Ok(vec![
        (Surface::Printed, printed.as_bytes().to_vec()),
        (Surface::Report, report.table.into_bytes()),
        (Surface::Receipt, report.receipt_bytes),
    ])
}

/// Synthetic mutation control. Plant every canary only in an in-memory copy
/// of each output surface; failures report fixed reasons and surface labels.
pub fn assert_memory_surfaces() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let controller = Controller {
        port: 0,
        printed: RefCell::default(),
        credentials: (0..3)
            .map(|index| format!("synthetic-{stamp}-{}-{index}", std::process::id()))
            .collect(),
        fixture: Fixture::committed().unwrap(),
        used: BTreeSet::new(),
        decisions: Decisions::default(),
    };
    let home = ThrowawayHome::new().unwrap();
    assert_eq!(
        controller.check_captures(&home),
        Err("capture inventory is empty")
    );
    home.launch(Path::new("/usr/bin/true"), &[], Duration::from_secs(1))
        .unwrap();
    controller.check_captures(&home).unwrap();
    let paths = home.capture_paths().unwrap();
    fs::remove_file(&paths[0][1]).unwrap();
    assert_eq!(
        controller.check_captures(&home),
        Err("expected capture is missing")
    );
    fs::write(&paths[0][1], b"").unwrap();
    let mut inventory = source_inventory().unwrap();
    let observations = [
        Observation::Native {
            role: "elastos".into(),
            sha256: "1".repeat(64),
        },
        Observation::Native {
            role: "localhost-provider".into(),
            sha256: "2".repeat(64),
        },
        Observation::Launched {
            probe: agent_conformance::identity::ProbeIdentity {
                effect: "default".into(),
                component_sha256: "3".repeat(64),
                bundle_lab_cid: format!("lab-cid:sha256:{}", "4".repeat(64)),
            },
        },
    ];
    inventory.extend(
        report_inventory(
            "default_activation_refuses_without_selector",
            &observations,
            "fixture read: synthetic surface control\n",
            true,
        )
        .unwrap(),
    );
    for (path, surface) in paths[0].iter().zip([Surface::Stdout, Surface::Stderr]) {
        inventory.push((surface, fs::read(path).unwrap()));
    }
    let required = [
        Surface::Printed,
        Surface::Report,
        Surface::Receipt,
        Surface::Committed,
        Surface::Candidate,
    ];
    controller.check_inventory(&inventory, &required).unwrap();
    for surface in required {
        let missing: Vec<_> = inventory
            .iter()
            .filter(|(label, _)| *label != surface)
            .cloned()
            .collect();
        assert_eq!(
            controller.check_inventory(&missing, &required),
            Err("required source or report inventory is empty")
        );
    }
    for surface in [
        Surface::Stdout,
        Surface::Stderr,
        Surface::Printed,
        Surface::Report,
        Surface::Receipt,
        Surface::Committed,
        Surface::Candidate,
    ] {
        let original = &inventory
            .iter()
            .find(|(label, _)| *label == surface)
            .unwrap()
            .1;
        for canary in &controller.credentials {
            let mut planted = original.clone();
            planted.extend_from_slice(canary.as_bytes());
            assert_eq!(
                controller.check_bytes(&planted, surface),
                Err(surface.refusal())
            );
        }
    }
    home.finish().unwrap();
}

fn require_empty_pending(response: &Value) -> Result<()> {
    let requests = response["requests"]
        .as_array()
        .ok_or("cleanup pending response requires a request list")?;
    if !requests.is_empty() {
        return Err("pending request leftover");
    }
    Ok(())
}

fn live_grant_state(response: &Value) -> Result<&'static str> {
    let grants = response["capabilities"]
        .as_array()
        .ok_or("cleanup grant response requires a capability list")?;
    // Future Runtime contract: the shell gets an explicit global live scope,
    // with exhausted/revoked grants filtered by Runtime. A local empty list
    // and audit events cannot substitute for that evidence.
    if response["scope"] != "all_sessions_live" {
        return Ok("pending:0 grants:BLOCKED(AC-021-GRANTS)");
    }
    if !grants.is_empty() {
        return Err("live grant leftover");
    }
    Ok("pending:0 grants:0")
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
    fn cleanup_state_refuses_pending_and_requires_global_live_grants() {
        assert_eq!(require_empty_pending(&json!({"requests": []})), Ok(()));
        assert_eq!(
            require_empty_pending(&json!({"requests": [{}]})),
            Err("pending request leftover")
        );
        assert!(require_empty_pending(&json!({})).is_err());
        assert!(live_grant_state(&json!({})).is_err());
        for capabilities in [json!([]), json!([{}])] {
            assert_eq!(
                live_grant_state(&json!({"capabilities": capabilities})),
                Ok("pending:0 grants:BLOCKED(AC-021-GRANTS)")
            );
        }
        assert_eq!(
            live_grant_state(&json!({"scope":"all_sessions_live", "capabilities": []})),
            Ok("pending:0 grants:0")
        );
        assert_eq!(
            live_grant_state(&json!({"scope":"all_sessions_live", "capabilities": [{}]})),
            Err("live grant leftover")
        );
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
            printed: RefCell::default(),
            credentials: vec!["fixture-canary".into()],
            fixture: fixture(),
            used: BTreeSet::new(),
            decisions: Decisions::default(),
        };
        assert!(controller
            .check_bytes(b"ordinary output", Surface::Stdout)
            .is_ok());
        assert!(
            controller
                .check_bytes(b"prefix fixture-canary suffix", Surface::Stderr)
                .is_err(),
            "credential checker must reject the in-memory canary"
        );
        assert!(!header_token("fixture\r\nheader"));
    }
}
