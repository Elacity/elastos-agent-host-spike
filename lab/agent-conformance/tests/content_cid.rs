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
//! (the Runtime's own `CapsuleManifest` parse and `validate`). The control uses
//! the same staging route with the same manifest minus that one key.
//!
//! Handover only: the Runtime manifest requirement type refuses `cid`, so
//! `requires_cid_is_refused_today` records that refusal. It goes red when the
//! Runtime reads the field, and the real journey in GAPS.md then takes over.

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

const GAP: &str = "gap: M2(e) content capsule named by its CID: the Runtime manifest reader refuses `requires[].cid` (Anders owns elastos-common; Sash's yes before that patch)";

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

/// The handover record. The Runtime manifest type parses every staged manifest
/// (`stage_probe` runs `capsule_identity::checked_bundle`, which runs that
/// type's own `serde` parse and `validate`), and it refuses `cid` in a
/// `requires[]` entry. This test is not ignored because it asserts today's
/// fact; it goes red when the Runtime reads `requires[].cid`.
#[test]
fn requires_cid_is_refused_today() {
    let before = content_listing();
    let right = content_cid();
    let home = ThrowawayHome::new().unwrap();
    let refusal = staging_refusal(&home, &viewer_manifest(&right), "viewer-content-cid");
    assert_eq!(
        refusal, "probe staging: bundle identity refused",
        "the staging refusal is the one bundle check, not a missing file"
    );
    let said = manifest_refusal(&viewer_manifest(&right));
    assert!(
        said.contains("unknown field `cid`") && said.contains("expected `name` or `kind`"),
        "the refusal must be the manifest reader's own field refusal, got: {said}"
    );
    home.finish().expect("finish the throwaway Home");
    eprintln!("{GAP}\nrefusal now: {said}");
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
    // `requires[0].cid` removed parses, so the refusal above is that key.
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
