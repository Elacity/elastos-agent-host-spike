//! wc-009a: the importing module and the lab grants files the verifier and
//! runner tests share. The module bytes and the grant pair live here once, so
//! no test file holds a second copy of either.

use std::fs;
use std::path::{Path, PathBuf};
use wasm_capsule_audit::DeclaredImport;
use wasm_capsule_tools::verify::{GRANTS_LABEL, GRANTS_SCHEMA};

/// A valid core module that imports one function, `env.f`, of type
/// `() -> ()`, and has nothing else.
pub const IMPORTING_MODULE: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic, version 1
    0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: one type, () -> ()
    0x02, 0x09, 0x01, // import section, 9 bytes, one import
    0x03, b'e', b'n', b'v', 0x01, b'f', 0x00, 0x00, // env.f, a function of type 0
];

/// The one import `IMPORTING_MODULE` has.
pub fn env_f() -> DeclaredImport {
    grant("env", "f")
}

/// The grant of `module`.`name`.
pub fn grant(module: &str, name: &str) -> DeclaredImport {
    DeclaredImport {
        module: module.into(),
        name: name.into(),
    }
}

/// A new file `name` in `folder` holding `text`, as a grants file to read.
pub fn write_grants(folder: &Path, name: &str, text: &str) -> PathBuf {
    let path = folder.join(name);
    fs::write(&path, text).expect("write a grants file");
    path
}

/// A new, well-formed lab grants file `name` in `folder` granting `grants`
/// (module, name) in order. It sits beside a bundle, never inside one.
pub fn grants_file(folder: &Path, name: &str, grants: &[(&str, &str)]) -> PathBuf {
    let imports: Vec<serde_json::Value> = grants
        .iter()
        .map(|(module, name)| serde_json::json!({ "module": module, "name": name }))
        .collect();
    let document = serde_json::json!({
        "schema": GRANTS_SCHEMA,
        "label": GRANTS_LABEL,
        "imports": imports,
    });
    write_grants(folder, name, &document.to_string())
}
