//! Identify the checkout's Runtime. `harness` owns every Runtime launch.

use crate::build::{lane, offline_build};
use std::fs::File;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug)]
pub struct RuntimeUnderTest {
    pub binary: PathBuf,
    pub sha256: String,
}

/// Cache failures too: each test process attempts at most one Runtime build.
/// The caller holds the repository's shared heavy-build lease.
pub fn runtime_under_test() -> Result<&'static RuntimeUnderTest, &'static str> {
    static RUNTIME: OnceLock<Result<RuntimeUnderTest, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(build_runtime)
        .as_ref()
        .map_err(String::as_str)
}

fn build_runtime() -> Result<RuntimeUnderTest, String> {
    let target = lane().join("target/runtime");
    let started = Instant::now();
    let output = offline_build("cargo", &target)
        .map_err(|error| format!("prepare Runtime build: {error}"))?
        .args([
            "build",
            "--locked",
            "--offline",
            "--manifest-path",
            "elastos/Cargo.toml",
            "-p",
            "elastos-server",
            "--bin",
            "elastos",
        ])
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .map_err(|error| format!("start Runtime build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Runtime build failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let binary = target.join("debug/elastos");
    // macOS supplies shasum. Hash the bytes through stdin, without running the
    // binary or adding a crate dependency to this std-only harness.
    let output = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(File::open(&binary).map_err(|error| format!("open built Runtime: {error}"))?)
        .output()
        .map_err(|error| format!("hash built Runtime: {error}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let hash = text.split_whitespace().next().unwrap_or("");
    if !output.status.success() || hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "Runtime SHA-256 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    println!(
        "elastos build finished in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    println!("elastos sha256:{hash}");
    Ok(RuntimeUnderTest {
        binary,
        sha256: hash.to_owned(),
    })
}
