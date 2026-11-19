//! A test-only Agent Host probe.
//!
//! The launch binds the principal; this component only shows what that
//! principal can reach through the bridge. It writes a format-2 journal entry
//! and `memory/notes.md` under its own `UsersAI` root through the protected
//! principal-root path, reads both back, and refuses to finish unless the
//! bytes come back. When the test plants a pointer under its own root, it
//! tries to read the pointer's URI, which is another agent's stored root, and
//! reports the bridge's refusal. When the test writes a plan under its own
//! root, it issues each planned request and records the answer.

wit_bindgen::generate!({
    path: "../../../../wit",
    world: "product-capsule-v1",
});

const JOURNAL: &str = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
const NOTES: &str = "localhost://UsersAI/self/memory/notes.md";
const PEER: &str = "localhost://UsersAI/self/memory/peer";
const PLAN: &str = "localhost://UsersAI/self/memory/plan";
const RESULTS: &str = "localhost://UsersAI/self/memory/results";

struct LaunchProbe;

impl LaunchProbe {
    fn grant(
        resource: &str,
        operation: &str,
    ) -> Result<String, elastos::bus::types::BusError> {
        let grant = elastos::bus::capabilities::request(&elastos::bus::types::CapabilityRequest {
            resource: resource.to_string(),
            actions: vec![operation.to_string()],
            reason: "a5-launch-probe".to_string(),
        })?;
        Ok(grant.id)
    }

    fn call(
        resource: &str,
        operation: &str,
        body: String,
    ) -> Result<(String, Vec<u8>), elastos::bus::types::BusError> {
        Self::call_with(resource, resource, operation, operation, body.into_bytes())
    }

    /// A call whose grant is asked for `grant_resource`, which may differ from
    /// the URI the invoke names and from its body path. The plan uses this so a
    /// cell can hold a grant for one root and name another.
    fn call_with(
        grant_resource: &str,
        resource: &str,
        operation: &str,
        action: &str,
        body: Vec<u8>,
    ) -> Result<(String, Vec<u8>), elastos::bus::types::BusError> {
        let grant = Self::grant(grant_resource, action)?;
        let response = elastos::bus::providers::invoke(&elastos::bus::types::InvokeRequest {
            resource: resource.to_string(),
            operation: operation.to_string(),
            body,
            grant: Some(grant),
        })?;
        Ok((response.status, response.body))
    }

    fn write(resource: &str, bytes: &[u8]) -> Result<(), elastos::bus::types::BusError> {
        let body = format!("\"content\":[{}]", numbers(bytes));
        let body = format!("{{{body}}}");
        let (status, response) = Self::call(resource, "write", body)?;
        match status.as_str() {
            "ok" => Ok(()),
            other => Err(elastos::bus::types::BusError::Denied(format!(
                "a5-launch-probe: write {resource} failed: {other} {}",
                String::from_utf8_lossy(&response)
            ))),
        }
    }

    fn read(resource: &str) -> Result<Vec<u8>, elastos::bus::types::BusError> {
        let (status, body) = Self::call(resource, "read", "{}".to_string())?;
        match status.as_str() {
            "ok" => content_bytes(&body).ok_or_else(|| {
                elastos::bus::types::BusError::Denied(format!(
                    "a5-launch-probe: read {resource} returned no content: {}",
                    String::from_utf8_lossy(&body)
                ))
            }),
            other => Err(elastos::bus::types::BusError::Denied(format!(
                "a5-launch-probe: read {resource} failed: {other} {}",
                String::from_utf8_lossy(&body)
            ))),
        }
    }

    /// Reads both own-root objects back and refuses unless they are the bytes
    /// that were written. The guest, not the host test, compares them.
    fn place(journal: &[u8], notes: &[u8]) -> Result<(), elastos::bus::types::BusError> {
        Self::write(JOURNAL, journal)?;
        Self::write(NOTES, notes)?;
        let read_journal = Self::read(JOURNAL)?;
        let read_notes = Self::read(NOTES)?;
        if read_journal != journal || read_notes != notes {
            return Err(elastos::bus::types::BusError::Denied(
                "a5-launch-probe: own-root objects did not read back".to_string(),
            ));
        }
        Ok(())
    }

    /// The pointer is a URI under its own root that names another agent's
    /// stored root. Asking the bridge for it is the attempt; the refusal is
    /// reported to the host, and an allowed read or grant is a failure.
    fn peer() -> Result<(), elastos::bus::types::BusError> {
        let Ok(pointer) = Self::read(PEER) else {
            return Ok(());
        };
        let Ok(peer) = String::from_utf8(pointer) else {
            return Err(elastos::bus::types::BusError::Denied(
                "a5-launch-probe: the peer pointer is not text".to_string(),
            ));
        };
        match Self::grant(&peer, "read") {
            Err(err) => Err(elastos::bus::types::BusError::Denied(format!(
                "a5-launch-probe: read of {peer} refused: {err:?}"
            ))),
            Ok(grant) => {
                let response =
                    elastos::bus::providers::invoke(&elastos::bus::types::InvokeRequest {
                        resource: peer.clone(),
                        operation: "read".to_string(),
                        body: b"{}".to_vec(),
                        grant: Some(grant),
                    });
                match response {
                    Ok(response) if response.status == "ok" => {
                        Err(elastos::bus::types::BusError::Denied(format!(
                            "a5-launch-probe: read of {peer} was allowed"
                        )))
                    }
                    Ok(response) => Err(elastos::bus::types::BusError::Denied(format!(
                        "a5-launch-probe: read of {peer} refused: {} {}",
                        response.status,
                        String::from_utf8_lossy(&response.body)
                    ))),
                    Err(err) => Err(elastos::bus::types::BusError::Denied(format!(
                        "a5-launch-probe: read of {peer} refused: {err:?}"
                    ))),
                }
            }
        }
    }

    /// Reads the plan the host wrote under this agent's own root, issues one
    /// request per line, and writes one result line per entry under the same
    /// root. A plan line is one of:
    ///
    /// - `request <resource> <action>`
    /// - `invoke <grant resource> <uri> <operation> <action> <body path>`
    /// - `send <grant resource> <uri> <operation> <action> <body path>`
    /// - `write <grant resource> <uri> <action> <text>`
    ///
    /// Fields are tab-separated; an empty body path means no body. An `invoke`
    /// line sends `{"path": <body path>}`. A `send` line reads the object at
    /// `<body path>` over the bridge and sends its bytes as they are, which is
    /// how a body the host wrote reaches the provider unwrapped. A missing
    /// plan leaves the probe's original behaviour untouched.
    fn plan() -> Result<(), elastos::bus::types::BusError> {
        let Ok(bytes) = Self::read(PLAN) else {
            return Ok(());
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut results = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let fields: Vec<&str> = line.split('\t').collect();
            let outcome = match fields.as_slice() {
                ["request", resource, action] => match Self::grant(resource, action) {
                    Ok(_) => "ok".to_string(),
                    Err(err) => format!("{err:?}"),
                },
                ["invoke", grant_resource, resource, operation, action, body_path] => {
                    let body = if body_path.is_empty() {
                        "{}".to_string()
                    } else {
                        format!("{{\"path\":\"{body_path}\"}}")
                    };
                    match Self::call_with(
                        grant_resource,
                        resource,
                        operation,
                        action,
                        body.into_bytes(),
                    ) {
                        Ok((status, response)) => {
                            format!("{status} {}", String::from_utf8_lossy(&response))
                        }
                        Err(err) => format!("{err:?}"),
                    }
                }
                ["send", grant_resource, resource, operation, action, body_path] => {
                    let sent = Self::read(body_path).and_then(|body| {
                        Self::call_with(grant_resource, resource, operation, action, body)
                    });
                    match sent {
                        Ok((status, response)) => {
                            format!("{status} {}", String::from_utf8_lossy(&response))
                        }
                        Err(err) => format!("{err:?}"),
                    }
                }
                ["write", grant_resource, resource, action, text] => {
                    let body = format!("{{\"content\":[{}]}}", numbers(text.as_bytes()));
                    match Self::call_with(
                        grant_resource,
                        resource,
                        "write",
                        action,
                        body.into_bytes(),
                    ) {
                        Ok((status, response)) => {
                            format!("{status} {}", String::from_utf8_lossy(&response))
                        }
                        Err(err) => format!("{err:?}"),
                    }
                }
                _ => continue,
            };
            results.push(format!("{index}\t{outcome}"));
        }
        Self::write(RESULTS, results.join("\n").as_bytes())
    }
}

impl exports::elastos::bus::lifecycle::Guest for LaunchProbe {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        let context = elastos::bus::identity::context();
        let principal = context.principal.unwrap_or_default();
        let mut journal = b"EAHJ".to_vec();
        journal.extend_from_slice(&2u16.to_le_bytes());
        journal.extend_from_slice(principal.as_bytes());
        let notes = format!("a5-launch-probe notes for {principal}");
        Self::place(&journal, notes.as_bytes())?;
        Self::peer()?;
        Self::plan()
    }
}

fn numbers(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The bytes a read result carries, from its `"content":[...]` array.
fn content_bytes(body: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(body).ok()?;
    let marker = "\"content\":[";
    let start = text.find(marker)? + marker.len();
    let end = start + text[start..].find(']')?;
    if end == start {
        return Some(Vec::new());
    }
    text[start..end]
        .split(',')
        .map(|value| value.parse().ok())
        .collect()
}

export!(LaunchProbe);
