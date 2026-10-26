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
        #[cfg(not(any(
            feature = "read",
            feature = "network",
            feature = "task",
            feature = "runaway"
        )))]
        {
            run_probe().map_err(|reason| elastos::bus::types::BusError::Unavailable(reason.into()))
        }
    }
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
        include_str!("../../fixtures/ungranted-read.txt").trim(),
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

#[cfg(target_arch = "wasm32")]
export!(Probe);

#[cfg(test)]
mod tests {
    #[test]
    fn probe_refuses_without_a_launch_argument_channel() {
        assert_eq!(
            super::run_probe(),
            Err("probe launch arguments are unavailable in elastos:bus@v1")
        );
    }
}
