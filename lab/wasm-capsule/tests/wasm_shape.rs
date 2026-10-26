//! Unit coverage for the shape reader itself, on crafted modules: it reads the
//! required shape, counts an import, sees an altered signature, rejects a
//! non-core file, and fails closed on a truncated module (PRINCIPLES P11).
//! Task 032: it reads a defined memory's minimum and maximum (or no maximum)
//! in pages, and fails closed on a truncated memory section.

mod common;

use common::wasm_shape::{read, FuncType, MemoryLimits, ValType};

const I32: u8 = 0x7f;
const I64: u8 = 0x7e;

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

fn type_section(ft: Vec<u8>) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(&ft);
    section(1, body)
}

fn function_section(type_index: u8) -> Vec<u8> {
    section(3, vec![1, type_index])
}

fn digest_export(func_index: u8) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(&name("digest"));
    body.push(0x00); // function kind
    body.push(func_index);
    section(7, body)
}

#[test]
fn reads_the_required_shape_from_a_crafted_module() {
    let module = core_module(&[
        type_section(functype(&[I32], &[I64])),
        function_section(0),
        digest_export(0),
    ]);
    let shape = read(&module).expect("shape");
    assert!(shape.is_core_wasm);
    assert_eq!(shape.import_count, 0);
    assert_eq!(
        shape.digest,
        Some(FuncType {
            params: vec![ValType::I32],
            results: vec![ValType::I64],
        })
    );
    assert!(shape.is_the_required_capsule_shape());
}

#[test]
fn counts_an_import_and_is_not_the_required_shape() {
    let mut import_body = vec![1];
    import_body.extend_from_slice(&name("env"));
    import_body.extend_from_slice(&name("f"));
    import_body.push(0x00); // function import
    import_body.push(0); // type index
    let module = core_module(&[type_section(functype(&[], &[])), section(2, import_body)]);
    let shape = read(&module).expect("shape");
    assert_eq!(shape.import_count, 1);
    assert!(!shape.is_the_required_capsule_shape());
}

#[test]
fn sees_an_altered_signature() {
    let module = core_module(&[
        type_section(functype(&[I32, I32], &[I64])),
        function_section(0),
        digest_export(0),
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

/// A memory section defining one memory with these limits. 1024 is the
/// two-byte LEB128 `0x80 0x08`; 16 fits in one byte.
fn memory_section(limits: &[u8]) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(limits);
    section(5, body)
}

#[test]
fn reads_a_memory_maximum_from_a_crafted_module() {
    // Flag 0x01: minimum 16 pages, maximum 1024 pages.
    let module = core_module(&[memory_section(&[0x01, 16, 0x80, 0x08])]);
    let shape = read(&module).expect("shape");
    assert_eq!(
        shape.memories,
        vec![MemoryLimits {
            minimum: 16,
            maximum: Some(1024),
        }]
    );
    assert_eq!(shape.imported_memory_count, 0);
}

#[test]
fn reads_a_memory_with_no_maximum_from_a_crafted_module() {
    // Flag 0x00: minimum 16 pages, no maximum.
    let module = core_module(&[memory_section(&[0x00, 16])]);
    let shape = read(&module).expect("shape");
    assert_eq!(
        shape.memories,
        vec![MemoryLimits {
            minimum: 16,
            maximum: None,
        }]
    );
}

#[test]
fn fails_closed_on_a_truncated_memory_section() {
    // The section is whole, but its one memory's flag 0x01 promises a maximum
    // that is not there.
    let module = core_module(&[memory_section(&[0x01, 16])]);
    assert_eq!(
        read(&module),
        Err("memory section: unexpected end of module".to_string())
    );
}
