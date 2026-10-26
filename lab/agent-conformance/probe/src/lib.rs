//! Intended selector: one of `read:<path>`, `net:<resource>`, `model:<resource>`,
//! or `address:<instance>`, with one Bus attempt and one result per activation.
//! Bus v1's lifecycle.run() has neither arguments nor a result payload or stdout.
//! The default activation explicitly refuses. Read/network builds request one
//! capability. Task/runaway builds compute locally, without requesting authority.

const _: () = assert!(
    cfg!(feature = "read") as u8
        + cfg!(feature = "network") as u8
        + cfg!(feature = "task") as u8
        + cfg!(feature = "runaway") as u8
        + cfg!(feature = "granted-read") as u8
        + cfg!(feature = "sibling-read") as u8
        + cfg!(feature = "memory-write") as u8
        <= 1,
    "select exactly one probe effect"
);

#[cfg(target_arch = "wasm32")]
wit_bindgen::generate!({
    path: "../../../elastos/wit",
    world: "product-capsule-v1",
});

/// Shared by the actual component entry point and its host regression test.
pub fn run_probe() -> Result<(), &'static str> {
    Err("probe launch arguments are unavailable in elastos:bus@v1")
}

#[cfg(target_arch = "wasm32")]
struct Probe;

#[cfg(target_arch = "wasm32")]
impl exports::elastos::bus::lifecycle::Guest for Probe {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        #[cfg(any(feature = "read", feature = "network"))]
        {
            request_effect()
        }
        #[cfg(feature = "task")]
        {
            run_task()
        }
        #[cfg(feature = "runaway")]
        {
            run_runaway()
        }
        #[cfg(feature = "memory-write")]
        {
            write_memory()
        }
        #[cfg(any(feature = "granted-read", feature = "sibling-read"))]
        {
            read_granted_file()
        }
        #[cfg(not(any(
            feature = "read",
            feature = "network",
            feature = "task",
            feature = "runaway",
            feature = "granted-read",
            feature = "sibling-read",
            feature = "memory-write"
        )))]
        {
            run_probe().map_err(|reason| elastos::bus::types::BusError::Unavailable(reason.into()))
        }
    }
}

#[cfg(all(
    target_arch = "wasm32",
    any(feature = "granted-read", feature = "sibling-read")
))]
fn read_granted_file() -> Result<(), elastos::bus::types::BusError> {
    use elastos::bus::{capabilities, providers, types::*};
    #[cfg(feature = "granted-read")]
    let resource = "localhost://Public/agent-conformance-grants/granted.txt";
    #[cfg(feature = "sibling-read")]
    let resource = "localhost://Public/agent-conformance-grants/sibling.txt";
    let grant = capabilities::request(&CapabilityRequest {
        resource: resource.into(),
        actions: vec!["read".into()],
        reason: "agent conformance: fixture read".into(),
    })?;
    if grant.resource != resource || grant.actions != ["read"] {
        return Err(BusError::Denied("fixture grant scope differs".into()));
    }
    let response = providers::invoke(&InvokeRequest {
        resource: resource.into(),
        operation: "read".into(),
        body: br#"{"encoding":"utf8"}"#.to_vec(),
        grant: Some(grant.id),
    })?;
    // Compare the complete serialized provider result, including all file bytes
    // and their length. The fixed ASCII fixture needs no guest JSON dependency.
    // Expected bytes stay independent of the host's mutable seed fixture.
    if response.status != "ok" {
        let reason = if response
            .body
            .windows(br#""code":"parse_error""#.len())
            .any(|part| part == br#""code":"parse_error""#)
        {
            "fixture provider parse error"
        } else if response
            .body
            .windows(br#""code":"read_failed""#.len())
            .any(|part| part == br#""code":"read_failed""#)
        {
            "fixture provider file read error"
        } else {
            "fixture provider read failed"
        };
        return Err(BusError::Unavailable(reason.into()));
    }
    if !fixture_bytes_match(&response.body) {
        return Err(BusError::Invalid(
            "granted file bytes differ from guest expectation".into(),
        ));
    }
    Ok(())
}

pub fn fixture_bytes_match(body: &[u8]) -> bool {
    body == br#"{"data":{"content":"grant-fixture-bytes","encoding":"utf8","size":19},"status":"ok"}"#
}

#[cfg(all(target_arch = "wasm32", feature = "task"))]
fn run_task() -> Result<(), elastos::bus::types::BusError> {
    // A build input, never a guest environment lookup or runtime selector.
    let index: usize = env!("AC_PROBE_TASK_INDEX").parse().unwrap();
    let line = include_str!("../../fixtures/parallel-tasks.txt")
        .lines()
        .nth(index)
        .unwrap();
    let fields: Vec<_> = line.split(',').collect();
    let left: u64 = fields[1].parse().unwrap();
    let right: u64 = fields[2].parse().unwrap();
    let result = std::hint::black_box(left) + std::hint::black_box(right);
    // Bus v1 has no success payload. This diagnostic completion deliberately
    // uses its error channel; the harness grades neither a grant nor success data.
    Err(elastos::bus::types::BusError::Unavailable(format!(
        "conformance completed {} result:{result}",
        fields[0]
    )))
}

#[cfg(all(target_arch = "wasm32", feature = "runaway"))]
fn run_runaway() -> Result<(), elastos::bus::types::BusError> {
    loop {
        std::hint::black_box(0_u32);
    }
}

#[cfg(all(target_arch = "wasm32", any(feature = "read", feature = "network")))]
fn request_effect() -> Result<(), elastos::bus::types::BusError> {
    use elastos::bus::{capabilities, types::CapabilityRequest};
    #[cfg(feature = "read")]
    let (resource, action) = (
        option_env!("AC_PROBE_READ_RESOURCE")
            .unwrap_or(include_str!("../../fixtures/ungranted-read.txt").trim()),
        "read",
    );
    #[cfg(feature = "network")]
    let (resource, action) = (
        include_str!("../../fixtures/ungranted-network.txt").trim(),
        "execute",
    );
    match capabilities::request(&CapabilityRequest {
        resource: resource.into(),
        actions: vec![action.into()],
        reason: "agent conformance: ungranted effect".into(),
    }) {
        // Success is observable by the host test, but this deny-only probe
        // stops here even if a grant arrives. It never reads or dials a target.
        Ok(_) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(all(target_arch = "wasm32", feature = "memory-write"))]
fn write_memory() -> Result<(), elastos::bus::types::BusError> {
    use elastos::bus::{capabilities, providers, types::*};
    let resource = include_str!("../../fixtures/memory-write.txt").trim();
    let grant = capabilities::request(&CapabilityRequest {
        resource: resource.into(),
        actions: vec!["write".into()],
        reason: "agent conformance: memory write".into(),
    })?;
    if grant.resource != resource || grant.actions != ["write"] {
        return Err(BusError::Denied("memory grant scope differs".into()));
    }
    let response = providers::invoke(&InvokeRequest {
        resource: resource.into(),
        operation: "write".into(),
        body: br#"{"content":[109,101,109,111,114,121],"create_only":true}"#.to_vec(),
        grant: Some(grant.id),
    })?;
    if response.status != "ok" {
        return Err(BusError::Unavailable("memory write failed".into()));
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
export!(Probe);

#[cfg(test)]
mod tests {
    #[test]
    fn guest_checks_all_granted_file_bytes() {
        let expected = br#"{"data":{"content":"grant-fixture-bytes","encoding":"utf8","size":19},"status":"ok"}"#;
        assert!(super::fixture_bytes_match(expected));
        for index in 0..expected.len() {
            let mut different = expected.to_vec();
            different[index] ^= 1;
            assert!(!super::fixture_bytes_match(&different));
        }
        assert!(!super::fixture_bytes_match(&expected[..expected.len() - 1]));
    }
    #[test]
    fn probe_refuses_without_a_launch_argument_channel() {
        assert_eq!(
            super::run_probe(),
            Err("probe launch arguments are unavailable in elastos:bus@v1")
        );
    }
}
