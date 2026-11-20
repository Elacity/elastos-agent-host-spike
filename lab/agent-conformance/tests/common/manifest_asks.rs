//! The fixture writer for typed manifest asks.
//!
//! A pair is one resource and one Runtime action word. Pairs that name one
//! resource become one `ManifestAsk`, in the order given. `capabilities` is
//! removed so the manifest has one ceiling. The shell grant stays the decision.

use std::path::Path;

/// Writes `pairs` onto `root`'s `capsule.json` as Runtime `asks`.
pub fn write_typed_manifest_asks(root: &Path, pairs: &[(&str, &str)]) {
    let path = root.join("capsule.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read capsule.json"))
            .expect("parse capsule.json");
    let object = document.as_object_mut().expect("capsule.json is an object");
    object.remove("capabilities");
    let mut asks: Vec<elastos_common::ManifestAsk> = Vec::new();
    for &(resource, action) in pairs {
        let action = elastos_common::AskAction::try_from(action.to_owned())
            .expect("a fixture action is a Runtime action");
        if let Some(ask) = asks.iter_mut().find(|ask| ask.resource == resource) {
            ask.actions.push(action);
        } else {
            asks.push(elastos_common::ManifestAsk {
                resource: resource.to_owned(),
                actions: vec![action],
            });
        }
    }
    object.insert(
        "asks".to_owned(),
        serde_json::to_value(&asks).expect("typed asks encode"),
    );
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_value(document.clone()).expect("the fixture manifest parses");
    manifest.validate().expect("the fixture manifest validates");
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&document).expect("encode capsule.json"),
    )
    .expect("write capsule.json");
}
