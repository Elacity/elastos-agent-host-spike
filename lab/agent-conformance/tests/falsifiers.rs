//! Each falsifier edits exact text and the runner requires that text to occur
//! exactly once in the file it names. A lint or refactor can move that text and
//! orphan a plant silently, so this test checks every edit that lands inside
//! this crate before the runner has to report NO MATCH.

use std::path::Path;

/// Entries whose edited text did not match before this check existed. Repair
/// each one in its own task; this list keeps them visible instead of hiding the
/// rest. An id leaves this list only when its edit matches again.
const KNOWN_STALE: [&str; 4] = [
    "F-census-a",
    "F-grant-http",
    "F-cleanup-temp",
    "F-cleanup-process",
];

#[test]
fn every_lab_falsifier_edit_still_applies() {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crate_root = crate_root.canonicalize().expect("the crate root resolves");
    let data = std::fs::read_to_string(crate_root.join("falsifiers.json"))
        .expect("falsifiers.json sits beside the crate manifest");
    let document: serde_json::Value = serde_json::from_str(&data).expect("falsifiers.json is JSON");
    let entries = document["falsifiers"]
        .as_array()
        .expect("falsifiers.json lists entries");

    // The runner reads `file` while its working directory is examples/agent-host.
    let lane_base = crate_root.join("../../examples/agent-host");
    let mut stale_ids = Vec::new();
    for entry in entries {
        let id = entry["id"].as_str().expect("every entry has an id");
        if KNOWN_STALE.contains(&id) {
            stale_ids.push(id);
            continue;
        }
        let edits = entry["edits"]
            .as_array()
            .unwrap_or_else(|| panic!("{id} lists its edits"));
        for edit in edits {
            let file = edit["file"].as_str().expect("every edit names a file");
            let target = lane_base
                .join(file)
                .canonicalize()
                .unwrap_or_else(|error| panic!("{id}: {file} does not resolve: {error}"));
            if !target.starts_with(&crate_root) {
                continue;
            }
            let old = edit["old"].as_str().expect("every edit has old text");
            let text = std::fs::read_to_string(&target)
                .unwrap_or_else(|error| panic!("{id}: {file} does not read: {error}"));
            let found = text.matches(old).count();
            assert_eq!(
                found, 1,
                "{id}: its old text occurs {found} times in {file}; a plant needs exactly one"
            );
        }
    }
    for id in KNOWN_STALE {
        assert!(
            stale_ids.contains(&id),
            "{id} is listed as stale but falsifiers.json has no such entry"
        );
    }
}
