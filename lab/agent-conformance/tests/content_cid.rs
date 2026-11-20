//! M2 exit (e) and PH6: a capsule opens a content capsule named by its CID.
//!
//! The pair is the repository's own viewer/content pair
//! (`templates/capsules/viewer-content/`): the viewer accepts a
//! `content_capsule`, and the content capsule names the data it serves. The
//! probe stands in for the viewer and names the content bundle's lab CID in
//! `requires[]`.
//!
//! Route: `stage_probe` stages the viewer probe through
//! `src/identity.rs::stage_probe`, which runs `capsule_identity::checked_bundle`
//! (the Runtime's own reader of a manifest that may pin a requirement,
//! `PinnedManifest::parse`, which checks each pin, parses the rest as
//! `CapsuleManifest` and calls `validate`). The control uses the same staging
//! route with the same manifest minus that one key.
//!
//! Handover only: the one bundle check now names a viewer bundle that pins
//! its content, which `a_viewer_that_pins_its_content_is_staged_and_named`
//! records, with a pin of the wrong form refused. Nothing launches content
//! by its CID yet; the real journey in GAPS.md is still owed.

#[allow(dead_code)]
mod common;
// The probe builder compiles every effect; this file builds one.
#[allow(dead_code)]
#[path = "common/probe.rs"]
mod probe;

use agent_conformance::build::{lane, repository};
use agent_conformance::harness::ThrowawayHome;
use agent_conformance::identity::MANIFEST;
use probe::{build_probe, Effect};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

// One probe output and one content directory exist per lane. Serialize builds,
// as `tests/effects.rs` does.
static PROBE_BUILD: Mutex<()> = Mutex::new(());

const GAP: &str = "gap: M2(e) content capsule named by its CID: a bundle that pins its content by CID is named, but no launch reads the pin or finds the content (the start by CID and its requirement closure are not built)";

/// The template pair: the viewer that accepts `content_capsule`, and the
/// content manifest with the viewer binding that acceptance requires.
fn template() -> PathBuf {
    repository().join("templates/capsules/viewer-content")
}

fn viewer_name() -> String {
    let viewer: Value = serde_json::from_slice(
        &fs::read(template().join("viewer.capsule.json")).expect("read the viewer template"),
    )
    .expect("the viewer template is JSON");
    viewer["name"]
        .as_str()
        .expect("the viewer template names itself")
        .to_owned()
}

/// The content bundle, copied into the lane with the one change the Runtime's
/// manifest type requires: `viewer` is the viewer's string name, as the
/// template's README states. The file bytes come from that one read.
static CONTENT: LazyLock<PathBuf> = LazyLock::new(|| {
    let staged = lane().join("target/content-cid-viewer-content");
    match fs::remove_dir_all(&staged) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("clean staged content: {error}"),
    }
    let source = template();
    let mut manifest: Value = serde_json::from_slice(
        &fs::read(source.join("content.capsule.json")).expect("read content template"),
    )
    .expect("the content template is JSON");
    assert_eq!(
        manifest["role"], "content",
        "the content capsule has the content role"
    );
    manifest["viewer"] = json!(viewer_name());
    fs::create_dir_all(&staged).expect("create staged content directory");
    fs::write(
        staged.join("capsule.json"),
        serde_json::to_vec_pretty(&manifest).expect("content manifest serializes"),
    )
    .expect("write content manifest");
    fs::copy(source.join("sample.example"), staged.join("sample.example"))
        .expect("copy the content payload at the manifest entrypoint");
    let checked = capsule_identity::checked_bundle(&staged).unwrap_or_else(|refusal| {
        panic!("the content copy must be a bundle the Runtime type accepts: {refusal}")
    });
    assert_eq!(
        checked.manifest_name(),
        "example-content",
        "the template content name"
    );
    staged
});

fn content_listing() -> Vec<capsule_identity::BundleEntry> {
    capsule_identity::checked_bundle(&CONTENT)
        .expect("read the content bundle")
        .entries()
        .to_vec()
}

fn content_cid() -> capsule_identity::LabCid {
    capsule_identity::lab_cid(&CONTENT).expect("the content bundle has a lab CID")
}

/// The probe's manifest, with the viewer binding and the content requirement.
fn viewer_manifest(content_cid: &capsule_identity::LabCid) -> Value {
    let mut manifest: Value = serde_json::from_slice(MANIFEST).expect("probe manifest is JSON");
    // The probe stays a wasm component capsule; only its acceptance binding
    // and its requirement change.
    manifest["name"] = json!(viewer_name());
    manifest["requires"] = json!([{
        "name": "example-content",
        "kind": "capsule",
        "cid": content_cid.to_string()
    }]);
    let mut interfaces = manifest["interfaces"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    interfaces.push(json!({
        "id": "example.viewer",
        "version": "1.0.0",
        "description": "Open the content capsule this viewer accepts",
        "methods": [{
            "id": "file.open",
            "description": "Open the required content capsule",
            "risk": "launch",
            "approval": "runtime_policy",
            "audit": "event",
            "resource": "elastos://content/asset",
            "operation": "open",
            "input_schema": { "schema": "example.file-open/v1", "accepts": [{
                "kind": "content_capsule",
                "role": "content",
                "type": "data",
                "viewer": viewer_name()
            }] },
            "output_schema": { "schema": "example.content-opened/v1", "content_type": "application/x-example", "viewer": viewer_name() }
        }]
    }));
    manifest["interfaces"] = Value::Array(interfaces);
    manifest
}

fn probe_bytes() -> Vec<u8> {
    let _serial = PROBE_BUILD
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    build_probe(Effect::Default, 1)
}

/// Stage a manifest through the route and return the route's refusal.
fn staging_refusal(home: &ThrowawayHome, manifest: &Value, label: &str) -> String {
    let bytes = probe_bytes();
    agent_conformance::identity::stage_probe(
        home,
        &bytes,
        &serde_json::to_vec(manifest).expect("manifest serializes"),
        label,
    )
    .err()
    .unwrap_or_else(|| panic!("the one bundle check must refuse the `{label}` manifest"))
}

/// The Runtime manifest type's words for a manifest that the one bundle check
/// refused. The bytes are the same bytes the route staged.
fn manifest_refusal(manifest: &Value) -> String {
    let scratch = lane().join("target/content-cid-manifest-check");
    let _ = fs::remove_dir_all(&scratch);
    fs::create_dir_all(&scratch).expect("create the manifest check directory");
    let entrypoint = manifest["entrypoint"]
        .as_str()
        .expect("entrypoint")
        .to_owned();
    fs::write(
        scratch.join("capsule.json"),
        serde_json::to_vec(manifest).expect("manifest serializes"),
    )
    .expect("write the checked manifest");
    fs::write(scratch.join(entrypoint), b"check-only").expect("write the entrypoint");
    let refusal = capsule_identity::checked_bundle(&scratch)
        .map(|_| "the bundle check accepted the manifest".to_owned())
        .unwrap_or_else(|refusal| refusal.to_string());
    let _ = fs::remove_dir_all(&scratch);
    refusal
}

/// The handover record, one step on. The bundle check reads a manifest with
/// the Runtime's own reader of pins (`stage_probe` runs
/// `capsule_identity::checked_bundle`, which runs `PinnedManifest::parse`), so
/// a viewer bundle that pins its content by CID is staged and named, and a
/// pin of the wrong form is refused in that reader's words. This test asserts
/// today's fact. It launches nothing: no launch reads a pin yet.
#[test]
fn a_viewer_that_pins_its_content_is_staged_and_named() {
    let before = content_listing();
    let right = content_cid();
    let manifest = viewer_manifest(&right);
    let bytes = probe_bytes();
    let stage = |home: &ThrowawayHome, manifest: &Value, label: &str| {
        agent_conformance::identity::stage_probe(
            home,
            &bytes,
            &serde_json::to_vec(manifest).expect("manifest serializes"),
            label,
        )
    };

    let home = ThrowawayHome::new().unwrap();
    let staged = stage(&home, &manifest, "viewer-content-cid")
        .expect("the one bundle check names a viewer bundle that pins its content");
    let named = capsule_identity::lab_cid(&staged.path).expect("the staged bundle has a lab CID");
    assert_eq!(
        staged.identity.bundle_lab_cid,
        named.to_string(),
        "the staged name is the bundle check's name of the staged folder"
    );

    // The pin is among the named bytes: the same manifest without it, staged
    // the same way with the same probe, has another name.
    let mut plain = manifest.clone();
    plain["requires"][0]
        .as_object_mut()
        .expect("the requirement is an object")
        .remove("cid");
    let plain_home = ThrowawayHome::new().unwrap();
    let unpinned = stage(&plain_home, &plain, "viewer-no-pin").expect("the control is a bundle");
    assert_ne!(
        unpinned.identity.bundle_lab_cid, staged.identity.bundle_lab_cid,
        "the pin is not among the bytes the name covers"
    );

    // A pin that is not a package root in its one spelling (here: capitals)
    // is refused by the same check, in the Runtime reader's own words.
    let mut wrong = manifest.clone();
    wrong["requires"][0]["cid"] = json!(right.to_string().to_uppercase());
    let wrong_home = ThrowawayHome::new().unwrap();
    assert_eq!(
        staging_refusal(&wrong_home, &wrong, "viewer-wrong-pin"),
        "probe staging: bundle identity refused",
        "the staging refusal is the one bundle check, not a missing file"
    );
    assert_eq!(
        manifest_refusal(&wrong),
        "the Runtime refuses the pinned manifest capsule.json (pin_form_invalid): requirement \"example-content\""
    );

    for home in [home, plain_home, wrong_home] {
        home.finish().expect("finish the throwaway Home");
    }
    eprintln!("{GAP}");
    let later = capsule_identity::checked_bundle(&CONTENT).expect("re-read the content");
    assert_eq!(before, later.entries(), "the staged content is unchanged");
    assert_eq!(
        right.to_string(),
        later.cid().to_string(),
        "the staged content keeps its name"
    );
}

#[test]
fn the_plain_staged_probe_is_still_a_bundle() {
    // The control: the same staged viewer manifest with only
    // `requires[0].cid` removed is a bundle too, as it was before the bundle
    // check could read a pin.
    let mut manifest = viewer_manifest(&content_cid());
    manifest["requires"][0]
        .as_object_mut()
        .expect("the requirement is an object")
        .remove("cid");
    assert_eq!(
        manifest["requires"],
        json!([{ "name": "example-content", "kind": "capsule" }]),
        "the control removes only the cid key"
    );
    let home = ThrowawayHome::new().unwrap();
    let bytes = probe_bytes();
    agent_conformance::identity::stage_probe(
        &home,
        &bytes,
        &serde_json::to_vec(&manifest).expect("manifest serializes"),
        "plain-requirement",
    )
    .expect("a requirement without a CID passes the same check");
    home.finish().expect("finish the throwaway Home");
}
