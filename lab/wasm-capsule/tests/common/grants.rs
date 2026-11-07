//! wc-009a: the importing module and the lab grants files the verifier and
//! runner tests share. The module bytes and the grants file form live here
//! once, so no test file holds a second copy of either. Task 065: no
//! core-module import is granted, so `IMPORTING_MODULE` is the module that is
//! refused, and a grants file names `resource` and `actions` (v3).

use std::fs;
use std::path::{Path, PathBuf};
use wasm_capsule_tools::verify::{GRANTS_LABEL, GRANTS_SCHEMA};

/// A valid core module that imports one function, `env.f`, of type
/// `() -> ()`, and has nothing else.
pub const IMPORTING_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version 1
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: one type, () -> ()
    0x02, 0x09, 0x01, // import section, 9 bytes, one import
    0x03, b'e', b'n', b'v', 0x01, b'f', 0x00, 0x00, // env.f, a function of type 0
];

/// The one module builder: `IMPORTING_MODULE`'s shape with its one import
/// named `module`.`name`, the same `() -> ()` function, under another name.
/// `importing("env", "f")` is `IMPORTING_MODULE` byte for byte. Each length
/// is one LEB128 byte, so the import section stays under 128 bytes.
pub fn importing(module: &str, name: &str) -> Vec<u8> {
    let mut import = vec![0x01]; // one import
    for part in [module, name] {
        assert!(part.len() < 0x80, "{part:?}: a length of one LEB128 byte");
        import.push(part.len() as u8);
        import.extend_from_slice(part.as_bytes());
    }
    import.extend_from_slice(&[0x00, 0x00]); // a function of type 0
    assert!(
        import.len() < 0x80,
        "the import section size is one LEB128 byte"
    );
    let size = import.len() as u8;
    let mut bytes = IMPORTING_MODULE[..14].to_vec(); // magic, version, type section
    bytes.extend_from_slice(&[0x02, size]);
    bytes.extend_from_slice(&import);
    bytes
}

/// A new file `name` in `folder` holding `text`, as a grants file to read.
pub fn write_grants(folder: &Path, name: &str, text: &str) -> PathBuf {
    let path = folder.join(name);
    fs::write(&path, text).expect("write a grants file");
    path
}

/// A new, well-formed lab grants file `name` in `folder` (v3) granting
/// `grants` (resource, actions) in order. It sits beside a bundle, never
/// inside one.
pub fn grants_file(folder: &Path, name: &str, grants: &[(&str, &[&str])]) -> PathBuf {
    let grants: Vec<serde_json::Value> = grants
        .iter()
        .map(|(resource, actions)| serde_json::json!({ "resource": resource, "actions": actions }))
        .collect();
    let document = serde_json::json!({
        "schema": GRANTS_SCHEMA,
        "label": GRANTS_LABEL,
        "grants": grants,
    });
    write_grants(folder, name, &document.to_string())
}
