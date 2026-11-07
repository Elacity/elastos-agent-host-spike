//! The built artifact has the shape wc-001 requires: a core Wasm module that
//! imports nothing (no ambient authority, PRINCIPLES P3) and exports `digest`
//! as `(param i32) -> (result i64)`.

mod common;

use common::build::{lane_dir, run_build, TempDir};
use common::wasm_shape::{self, FuncType, ValType};
use std::fs;
use wasm_capsule_audit::audit;

/// Task 053: the imports are read only through `wasm_capsule_audit::audit`,
/// the lab's one module reader (P10). With no import declared, it returns an
/// empty list or refuses the first import by name; the test-only shape reader
/// reads no imports and checks only core Wasm and the `digest` signature.
#[test]
fn built_capsule_has_the_required_wasm_shape() {
    let lane = lane_dir();
    let tmp = TempDir::new("shape");
    let out = tmp.path().join("out");
    run_build(&lane, &out);

    let bytes = fs::read(out.join("capsule.wasm")).expect("read capsule.wasm");
    let imports = audit(&bytes, &[]).map_err(|refusal| refusal.to_string());
    assert_eq!(
        imports,
        Ok(Vec::new()),
        "the capsule must import nothing: the one audit reader's import list or refusal is {imports:?}"
    );
    let shape = wasm_shape::read(&bytes).expect("read wasm shape");

    assert!(
        shape.is_core_wasm,
        "the artifact must be a core Wasm module"
    );
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I64],
        }),
        "digest must be (param i32) -> (result i64)"
    );
    assert_eq!(
        shape.lifecycle_run,
        Some(FuncType {
            params: vec![],
            results: vec![ValType::I32],
        }),
        "elastos:bus/lifecycle@1.0.0#run must be () -> (result i32)"
    );
    assert!(
        shape.is_the_required_capsule_shape(),
        "the artifact must have the full required capsule shape"
    );
}
