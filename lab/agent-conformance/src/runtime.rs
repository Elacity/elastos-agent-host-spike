//! Build and identify the Runtime once per test process; never launch it here.

use crate::build::offline_build;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Instant;

pub struct RuntimeUnderTest {
    pub binary: PathBuf,
    pub sha256: String,
}

/// A build failure is cached too: every caller sees Cargo's output, without
/// retrying the heavy build. The caller holds the repository's build lease.
pub fn runtime_under_test() -> &'static RuntimeUnderTest {
    static RUNTIME: OnceLock<Result<RuntimeUnderTest, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(build_runtime)
        .as_ref()
        .unwrap_or_else(|error| panic!("{error}"))
}

fn build_runtime() -> Result<RuntimeUnderTest, String> {
    let lane = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = lane.parent().unwrap().parent().unwrap();
    let target = lane.join("target/runtime");
    let mut command = Command::new("cargo");
    offline_build(&mut command, &target).map_err(|error| error.to_string())?;
    let started = Instant::now();
    let output = command
        .args(["build", "--locked", "--offline", "--manifest-path"])
        .arg(root.join("elastos/Cargo.toml"))
        .args(["-p", "elastos-server", "--bin", "elastos"])
        .current_dir(root.join("elastos"))
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("could not start Runtime build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Runtime build failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let binary = target.join("debug/elastos");
    // The supported Mac supplies shasum. Hash stdin so its output names only
    // these bytes; no Cargo dependency or cross-machine constant is needed.
    let hash = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(File::open(&binary).map_err(|error| error.to_string())?)
        .output()
        .map_err(|error| format!("could not hash Runtime: {error}"))?;
    if !hash.status.success() {
        return Err(format!(
            "Runtime SHA-256 failed: {}",
            String::from_utf8_lossy(&hash.stderr)
        ));
    }
    let sha256 = String::from_utf8(hash.stdout)
        .map_err(|error| error.to_string())?
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("Runtime SHA-256 output is invalid")?
        .to_owned();
    println!("elastos sha256:{sha256}");
    println!(
        "Runtime build and hash: {:.2}s",
        started.elapsed().as_secs_f64()
    );
    Ok(RuntimeUnderTest { binary, sha256 })
}
