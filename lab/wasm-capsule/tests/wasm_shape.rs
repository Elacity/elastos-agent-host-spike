//! Unit coverage for the shape reader itself, on crafted modules: it reads the
//! required shape, refuses a module with an import section (it reads no
//! imports, task 053), sees an altered signature, rejects a non-core file, and
//! fails closed on a truncated module (PRINCIPLES P11). Task 068 adds the
//! world's `elastos:bus/lifecycle@1.0.0#run` export: a module whose `digest`
//! signature is right and whose lifecycle signature is not is refused.

mod common;

use common::wasm_shape::{read, FuncType, ValType, LIFECYCLE_RUN_EXPORT};

const I32: u8 = 0x7f;
const I64: u8 = 0x7e;

/// The export name as the helpers below spell it; the reader's constant holds
/// the same bytes.
const LIFECYCLE_RUN: &str = "elastos:bus/lifecycle@1.0.0#run";

fn core_module(sections: &[Vec<u8>]) -> Vec<u8> {
    let mut m = vec![0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];
    for section in sections {
        m.extend_from_slice(section);
    }
    m
}

// All counts and lengths in these crafted modules are below 128, so a single
// byte is their LEB128 encoding.
fn section(id: u8, body: Vec<u8>) -> Vec<u8> {
    assert!(body.len() < 128);
    let mut s = vec![id, body.len() as u8];
    s.extend_from_slice(&body);
    s
}

fn name(text: &str) -> Vec<u8> {
    let mut v = vec![text.len() as u8];
    v.extend_from_slice(text.as_bytes());
    v
}

fn functype(params: &[u8], results: &[u8]) -> Vec<u8> {
    let mut v = vec![0x60, params.len() as u8];
    v.extend_from_slice(params);
    v.push(results.len() as u8);
    v.extend_from_slice(results);
    v
}

fn type_section(functypes: &[Vec<u8>]) -> Vec<u8> {
    let mut body = vec![functypes.len() as u8];
    for ft in functypes {
        body.extend_from_slice(ft);
    }
    section(1, body)
}

fn function_section(type_indices: &[u8]) -> Vec<u8> {
    let mut body = vec![type_indices.len() as u8];
    body.extend_from_slice(type_indices);
    section(3, body)
}

/// One export section holding every `(name, function index)` pair in order.
fn export_section(entries: &[(&str, u8)]) -> Vec<u8> {
    let mut body = vec![entries.len() as u8];
    for (text, func_index) in entries {
        body.extend_from_slice(&name(text));
        body.push(0x00); // function kind
        body.push(*func_index);
    }
    section(7, body)
}

/// The right `digest` type and the right lifecycle `run` type: the required
/// shape.
fn required_types() -> Vec<Vec<u8>> {
    vec![functype(&[I32], &[I64]), functype(&[], &[I32])]
}

/// The required shape's sections: two functions and the two exports.
fn required_shapes() -> Vec<Vec<u8>> {
    vec![
        type_section(&required_types()),
        function_section(&[0, 1]),
        export_section(&[("digest", 0), (LIFECYCLE_RUN, 1)]),
    ]
}

#[test]
fn reads_the_required_shape_from_a_crafted_module() {
    assert_eq!(LIFECYCLE_RUN_EXPORT, LIFECYCLE_RUN.as_bytes());
    let module = core_module(&required_shapes());
    let shape = read(&module).expect("shape");
    assert!(shape.is_core_wasm);
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I64],
        })
    );
    assert_eq!(
        shape.lifecycle_run,
        Some(FuncType {
            params: vec![],
            results: vec![ValType::I32],
        })
    );
    assert!(shape.is_the_required_capsule_shape());
}

/// Task 053: the shape reader reads no imports, so it refuses this one-import
/// module with its one exact reason, which names the one import reader.
#[test]
fn refuses_a_module_with_an_import_section() {
    let mut import_body = vec![1];
    import_body.extend_from_slice(&name("env"));
    import_body.extend_from_slice(&name("f"));
    import_body.push(0x00); // function import
    import_body.push(0); // type index
    let module = core_module(&[type_section(&[functype(&[], &[])]), section(2, import_body)]);
    assert_eq!(
        read(&module),
        Err(
            "the shape reader reads no imports: a module's imports are read only \
             through wasm_capsule_audit::audit"
                .to_string()
        ),
        "a module with an import section must be refused, not read"
    );
}

#[test]
fn sees_an_altered_signature() {
    let module = core_module(&[
        type_section(&[functype(&[I32, I32], &[I64]), functype(&[], &[I32])]),
        function_section(&[0, 1]),
        export_section(&[("digest", 0), (LIFECYCLE_RUN, 1)]),
    ]);
    let shape = read(&module).expect("shape");
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32, ValType::I32],
            results: vec![ValType::I64],
        })
    );
    assert!(!shape.is_the_required_capsule_shape());
}

/// Task 068: the lifecycle signature is part of the required shape. A module
/// whose `digest` signature is right and whose
/// `elastos:bus/lifecycle@1.0.0#run` signature is not `() -> (i32)` is refused.
/// Deleting the export is a different test: componentize can fail on a missing
/// export while this signature check is broken.
#[test]
fn rejects_wrong_lifecycle_signature() {
    let module = core_module(&[
        // `digest` is right; `run` takes an `i32`, which the world's
        // `func() -> result<_, bus-error>` does not.
        type_section(&[functype(&[I32], &[I64]), functype(&[I32], &[I32])]),
        function_section(&[0, 1]),
        export_section(&[("digest", 0), (LIFECYCLE_RUN, 1)]),
    ]);
    let shape = read(&module).expect("shape");
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I64],
        }),
        "the crafted module's `digest` signature is the right one"
    );
    assert_eq!(
        shape.lifecycle_run,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I32],
        }),
        "the crafted module's lifecycle signature is the wrong one"
    );
    assert!(
        !shape.is_the_required_capsule_shape(),
        "a wrong `elastos:bus/lifecycle@1.0.0#run` signature must not pass the required shape"
    );
}

#[test]
fn rejects_non_core_wasm() {
    // The component-model binary shares the magic but carries version 0x0d.
    let component = [0x00, b'a', b's', b'm', 0x0d, 0x00, 0x01, 0x00];
    let shape = read(&component).expect("shape");
    assert!(!shape.is_core_wasm);
    assert!(!shape.is_the_required_capsule_shape());
}

#[test]
fn fails_closed_on_a_truncated_module() {
    // Section id 1 claims five body bytes but only one follows.
    let truncated = core_module(&[vec![1, 5, 0x60]]);
    assert!(read(&truncated).is_err());
}
