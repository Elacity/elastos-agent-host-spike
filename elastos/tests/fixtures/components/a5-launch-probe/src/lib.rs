//! A test-only Agent Host probe.
//!
//! The launch binds the principal; this component only shows what that
//! principal can reach through the bridge. It writes a format-2 journal entry
//! and `memory/notes.md` under its own `UsersAI` root through the protected
//! principal-root path, reads both back, and refuses to finish unless the
//! bytes come back. When the test plants a pointer under its own root, it
//! tries to read the pointer's URI, which is another agent's stored root, and
//! reports the bridge's refusal.

wit_bindgen::generate!({
    path: "../../../../wit",
    world: "product-capsule-v1",
});

const JOURNAL: &str = "localhost://UsersAI/self/.AppData/Agents/agent-host/tasks/t1/journal";
const NOTES: &str = "localhost://UsersAI/self/memory/notes.md";
const PEER: &str = "localhost://UsersAI/self/memory/peer";

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
        let grant = Self::grant(resource, operation)?;
        let response = elastos::bus::providers::invoke(&elastos::bus::types::InvokeRequest {
            resource: resource.to_string(),
            operation: operation.to_string(),
            body: body.into_bytes(),
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
        Self::peer()
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
