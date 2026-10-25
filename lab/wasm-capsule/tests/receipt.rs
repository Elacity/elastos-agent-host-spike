//! The receipt binds the artifact to the exact toolchain and inputs, so a
//! rebuild can be checked against it (PRINCIPLES P13).

mod common;

use common::build::{lane_dir, run_build, rustc_version, sha256_file, Receipt, TempDir};

#[test]
fn the_receipt_names_the_exact_toolchain() {
    let lane = lane_dir();
    let tmp = TempDir::new("receipt-toolchain");
    let out = tmp.path().join("out");
    run_build(&lane, &out);
    let receipt = Receipt::read(&out);

    assert_eq!(
        receipt.get("rustc_version"),
        rustc_version(&lane),
        "the receipt must name the exact compiler tools/build used"
    );
    assert_eq!(
        receipt.get("target"),
        "wasm32-unknown-unknown",
        "the receipt must name the build target"
    );
}

#[test]
fn receipt_hashes_match_artifact_and_lockfile() {
    let lane = lane_dir();
    let tmp = TempDir::new("receipt-hashes");
    let out = tmp.path().join("out");
    run_build(&lane, &out);
    let receipt = Receipt::read(&out);

    assert_eq!(
        receipt.get("artifact_sha256"),
        sha256_file(&out.join("capsule.wasm")),
        "the receipt's artifact hash must match the built capsule"
    );
    assert_eq!(
        receipt.get("lockfile_sha256"),
        sha256_file(&lane.join("Cargo.lock")),
        "the receipt's lockfile hash must match Cargo.lock"
    );
}
