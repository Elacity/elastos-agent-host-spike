//! Shared offline build environment. Runtime launches belong to `harness`.

use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;

/// Keep both Cargo artifacts and intermediates in the caller's lane target.
/// Builds retain the developer's normal toolchain environment.
pub fn offline_build(command: &mut Command, target: &Path) -> io::Result<()> {
    fs::create_dir_all(target.join("tmp"))?;
    command
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
        .env("TMPDIR", target.join("tmp"))
        .env("CARGO_INCREMENTAL", "0");
    Ok(())
}
