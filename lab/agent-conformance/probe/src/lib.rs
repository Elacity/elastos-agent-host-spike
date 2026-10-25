//! Intended selector: one of `read:<path>`, `net:<resource>`, `model:<resource>`,
//! or `address:<instance>`, with one Bus attempt and one result per activation.
//! Bus v1's lifecycle.run() has neither arguments nor a result payload or stdout.
//! Until Runtime supplies that channel, activation explicitly refuses. A build
//! is evidence of a valid component, not evidence that an effect was attempted.

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
        run_probe().map_err(|reason| elastos::bus::types::BusError::Unavailable(reason.into()))
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
