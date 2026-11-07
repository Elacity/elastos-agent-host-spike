//! M1 red team: the manifest bound that A8's journey asserts.
//!
//! `test_m1_runtime.py` copies this file into a scratch clone as
//! `elastos/crates/elastos-server/src/redteam_m1_bridge.rs` and declares it from
//! that clone's `resource_bridge.rs` as a test-only child module. No Runtime
//! source in this repository changes.
//!
//! `host_key_read_is_refused` (#179) requires the lifecycle reason
//! `Internal("capsule manifest does not declare authority for <resource>")`
//! for `localhost://Public/../../../../.ssh/id_ed25519`, with the probe's
//! manifest declaring `localhost://Public/agent-conformance-grants/*`.

use super::*;

const MANIFEST: &str = "localhost://Public/agent-conformance-grants/*";
const HOST_KEY: &str = "localhost://Public/../../../../.ssh/id_ed25519";
const ORDINARY: &str = "localhost://Public/an-ordinary-undeclared-file.txt";

fn declared() -> Vec<String> {
    vec![MANIFEST.to_string()]
}

#[test]
fn control_the_manifest_bound_refuses_both_resources() {
    assert!(!manifest_allows_resource(&declared(), HOST_KEY, None));
    assert!(!manifest_allows_resource(&declared(), ORDINARY, None));
    assert!(manifest_allows_resource(
        &declared(),
        "localhost://Public/agent-conformance-grants/granted.txt",
        None
    ));
}

#[test]
fn control_a_parent_segment_under_the_declared_prefix_is_refused() {
    assert!(!manifest_allows_resource(
        &declared(),
        "localhost://Public/agent-conformance-grants/../../../../../.ssh/id_ed25519",
        None
    ));
}

/// FM-A8. The refusal A8's journey requires is the generic manifest bound:
/// with the resource text replaced, an ordinary undeclared file gets the same
/// code and the same sentence. The journey would pass for any undeclared
/// resource, so its required reason says nothing about host files.
#[test]
fn fm_a8_the_asserted_refusal_is_specific_to_a_host_file() {
    let shape = |resource: &str| {
        manifest_denied_response(resource)
            .to_string()
            .replace(resource, "<resource>")
    };
    assert_ne!(
        shape(HOST_KEY),
        shape(ORDINARY),
        "the host-key refusal and an ordinary undeclared file's refusal are the same response"
    );
}
