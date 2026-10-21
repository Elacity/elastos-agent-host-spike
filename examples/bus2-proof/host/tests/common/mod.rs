//! Shared by the proof tests: the built guests, componentized.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A guest's core module from `target/wasm32-unknown-unknown/release`,
/// componentized. `verify.sh` builds the guests first.
pub fn guest(name: &str) -> Vec<u8> {
    let path = root()
        .join("target/wasm32-unknown-unknown/release")
        .join(format!("{name}.wasm"));
    let core = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "{}: {err}; build the guests first (./verify.sh)",
            path.display()
        )
    });
    bus2_host::componentize(&core).unwrap()
}

pub fn fixture(name: &str) -> Vec<u8> {
    wat::parse_file(root().join("fixtures").join(name)).unwrap()
}
