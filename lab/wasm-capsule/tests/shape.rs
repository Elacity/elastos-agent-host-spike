//! The built artifact has the shape wc-001 requires: a core Wasm module that
//! imports nothing (no ambient authority, PRINCIPLES P3) and exports `digest`
//! as `(param i32) -> (result i64)`.

mod common;

use common::build::{lane_dir, run_build, TempDir};
use common::wasm_shape::{self, FuncType, ValType};
use std::fs;

#[test]
fn built_capsule_has_the_required_wasm_shape() {
    let lane = lane_dir();
    let tmp = TempDir::new("shape");
    let out = tmp.path().join("out");
    run_build(&lane, &out);

    let bytes = fs::read(out.join("capsule.wasm")).expect("read capsule.wasm");
    let shape = wasm_shape::read(&bytes).expect("read wasm shape");

    assert!(
        shape.is_core_wasm,
        "the artifact must be a core Wasm module"
    );
    assert_eq!(shape.import_count, 0, "the capsule must import nothing");
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I64],
        }),
        "digest must be (param i32) -> (result i64)"
    );
    assert!(
        shape.is_the_required_capsule_shape(),
        "the artifact must have the full required capsule shape"
    );
}
