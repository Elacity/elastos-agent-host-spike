wit_bindgen::generate!({
    path: "../../../../wit",
    world: "product-capsule-v1",
});

const RESOURCE: &str = "elastos://test/bus/probe";

struct LaunchProbe;

impl exports::elastos::bus::lifecycle::Guest for LaunchProbe {
    fn run() -> Result<(), elastos::bus::types::BusError> {
        // One call reaches the bridge, which audits it under the principal the
        // launch bound. The refusal is the point: the call is what is seen.
        let _ = elastos::bus::providers::invoke(&elastos::bus::types::InvokeRequest {
            resource: RESOURCE.to_string(),
            operation: "read".to_string(),
            body: br#"{"probe":"a5-launch-probe"}"#.to_vec(),
            // A grant id the bridge does not know: the call still reaches it,
            // and its audit names the launch principal.
            grant: Some("grant:a5-launch-probe".to_string()),
        });
        Ok(())
    }
}

export!(LaunchProbe);
