//! The committed fixtures: their manifests pass the Runtime's own checks,
//! each gets its pinned lab CID, and a bundle around wc-001's built module
//! gets a stable one.
mod common;

use std::fs;

use capsule_identity::lab_cid;
use common::*;
use elastos_common::CapsuleManifest;
use sha2::{Digest, Sha256};

#[test]
fn fixture_manifests_parse_and_validate_with_the_runtime_type() {
    // Every fixture folder is listed in FIXTURES, so none can skip this check.
    let mut folders: Vec<String> = fs::read_dir(lane_dir().join("fixtures"))
        .expect("list fixtures/")
        .map(|item| item.expect("read a fixtures/ entry"))
        .filter(|item| item.file_type().expect("fixture type").is_dir())
        .map(|item| item.file_name().into_string().expect("UTF-8 fixture name"))
        .collect();
    folders.sort();
    let mut listed: Vec<&str> = FIXTURES.iter().map(|fixture| fixture.name).collect();
    listed.sort();
    assert_eq!(folders, listed);

    for fixture in FIXTURES {
        let bytes = read_fixture(fixture, "capsule.json");
        let manifest: CapsuleManifest = serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            panic!(
                "{}: the Runtime type refused capsule.json: {error}",
                fixture.name
            )
        });
        manifest.validate().unwrap_or_else(|error| {
            panic!("{}: validate() refused capsule.json: {error}", fixture.name)
        });
    }
}

#[test]
fn lab_cid_matches_the_pinned_value_for_each_fixture() {
    for (fixture, pinned) in [
        (&CONTENT_SAMPLE, CONTENT_SAMPLE_LAB_CID),
        (&WEB_APP, WEB_APP_LAB_CID),
    ] {
        // Two copies in two temp folders, each named twice: the folder's
        // path and the moment of naming never enter the value.
        for _copy in 0..2 {
            let bundle = assemble(fixture);
            for _naming in 0..2 {
                let named = lab_cid(bundle.path())
                    .unwrap_or_else(|refusal| panic!("{}: {refusal}", fixture.name));
                assert_eq!(
                    named.to_string(),
                    pinned,
                    "{} in {}",
                    fixture.name,
                    bundle.path().display()
                );
            }
        }
    }
}

#[test]
fn wc001_capsule_bundle_gets_a_stable_lab_cid() {
    let out = temp_dir();
    let module = wc001_module(out.path());
    assert!(
        module.starts_with(b"\0asm\x01\0\0\0"),
        "wc-001's output is not a core Wasm module of version 1"
    );
    let receipt = fs::read_to_string(out.path().join("receipt.txt")).expect("read receipt.txt");
    let recorded = receipt
        .lines()
        .find_map(|line| line.strip_prefix("artifact_sha256:"))
        .map(str::trim)
        .expect("receipt.txt has an artifact_sha256 line");
    assert_eq!(
        hex::encode(Sha256::digest(&module)),
        recorded,
        "capsule.wasm is not the module wc-001's receipt names"
    );

    // wc-001's hash is that lane's value and differs per machine, so it is
    // not pinned here: two bundles around it, each named twice, agree.
    let mut names = Vec::new();
    for _copy in 0..2 {
        let bundle = assemble(&WC001_CORE);
        write_file(bundle.path(), "capsule.wasm", &module);
        for _naming in 0..2 {
            names.push(lab_cid(bundle.path()).expect("name the wc-001 bundle"));
        }
    }
    assert!(names.windows(2).all(|pair| pair[0] == pair[1]), "{names:?}");
}
