//! The lane's foundation claim: two clean builds of the same source, in
//! different paths, are byte-identical on this one Mac (PRINCIPLES P13).

mod common;

use common::build::{copy_lane_source, lane_dir, run_build, sha256_file, TempDir};
use std::fs;

#[test]
fn two_clean_builds_in_different_paths_are_byte_identical() {
    let lane = lane_dir();
    let a = TempDir::new("repro-a");
    let b = TempDir::new("repro-b");

    // Two copies of the lane source at two different absolute paths, each under
    // a directory whose name has a space, so the build must not split that path
    // on whitespace when it passes --remap-path-prefix to rustc. Each copy is
    // laid out as `<root>/lab/wasm-capsule`, with the out-of-lane path
    // dependencies reachable from it (`copy_lane_source`).
    let root_a = a.path().join("capsule lab");
    let root_b = b.path().join("capsule lab");
    fs::create_dir_all(&root_a).expect("create root_a");
    fs::create_dir_all(&root_b).expect("create root_b");
    let lane_a = copy_lane_source(&lane, &root_a);
    let lane_b = copy_lane_source(&lane, &root_b);
    assert_ne!(lane_a, lane_b, "the two copies must be at different paths");

    // Build each from its own empty out dir; tools/build uses a fresh target.
    let out_a = a.path().join("out");
    let out_b = b.path().join("out");
    run_build(&lane_a, &out_a);
    run_build(&lane_b, &out_b);

    let wasm_a = out_a.join("capsule.wasm");
    let wasm_b = out_b.join("capsule.wasm");
    let sha_a = sha256_file(&wasm_a);
    let sha_b = sha256_file(&wasm_b);
    assert_eq!(
        sha_a, sha_b,
        "two clean builds in different paths must have the same sha256"
    );
    // Byte equality is the real claim; the sha is only for a readable message.
    assert_eq!(
        fs::read(&wasm_a).expect("read a"),
        fs::read(&wasm_b).expect("read b"),
        "the two artifacts differ in bytes"
    );
}
