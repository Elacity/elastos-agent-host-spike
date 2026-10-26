//! Intended selector: one of `read:<path>`, `net:<resource>`, `model:<resource>`,
//! or `address:<instance>`, with one Bus attempt and one result per activation.
//! Bus v1's lifecycle.run() has neither arguments nor a result payload or stdout.
//! The default activation explicitly refuses. Effect builds request exactly one
//! capability; Runtime owns the decision and the guest returns its Bus error.

#[cfg(all(feature = "read", feature = "network"))]
compile_error!("select exactly one probe effect: read or network");

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
        #[cfg(not(any(feature = "read", feature = "network")))]
        {
            run_probe().map_err(|reason| elastos::bus::types::BusError::Unavailable(reason.into()))
        }
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
