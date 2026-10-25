//! Offline builds keep the developer's toolchain and lane-owned outputs.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn lane() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn repository() -> PathBuf {
    lane().parent().unwrap().parent().unwrap().to_path_buf()
}

/// Shared by the probe and Runtime builds; this is not a Runtime launch.
pub fn offline_build(program: &str, target: &Path) -> io::Result<Command> {
    fs::create_dir_all(target.join("tmp"))?;
    let mut command = Command::new(program);
    command
        .current_dir(repository())
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", target)
        .env("CARGO_BUILD_BUILD_DIR", target.join("build"))
        .env("TMPDIR", target.join("tmp"))
        .env("CARGO_INCREMENTAL", "0");
    Ok(command)
}
