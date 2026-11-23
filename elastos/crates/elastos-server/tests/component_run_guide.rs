//! The Component commands printed in the authoring guide. This check reads the
//! guide text, so it runs on every platform; the CLI journey that follows the
//! guide is Unix only (`component_run_commands.rs`).

use std::fs;

#[test]
fn documented_guide_lists_the_stage_then_run_commands() {
    // Read at run time: Rust sources outside lab/ must not embed notes (scripts/ci-installed-app-paths-test.py).
    // A Windows checkout can hold CRLF text, so compare the guide with `\n`.
    let guide = fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/CAPSULE_AUTHORING.md"),
    )
    .unwrap()
    .replace("\r\n", "\n");
    assert!(guide.contains("mkdir my-app-bundle"));
    assert!(guide.contains("cp my-app/capsule.json my-app/my-app.component.wasm my-app-bundle/"));
    assert!(guide.contains("elastos config set dev_mode false"));
    assert!(guide.contains("elastos stage-bundle my-app-bundle\n"));
    assert!(guide.contains("elastos stage-bundle my-app-bundle --signature my-app-bundle.sig.json"));
    assert!(guide.contains("elastos run my-app-bundle"));
    assert!(guide.contains("elastos config set dev_mode true"));
    assert!(guide.contains("elastos run --dev-unsigned-component my-app"));
}
