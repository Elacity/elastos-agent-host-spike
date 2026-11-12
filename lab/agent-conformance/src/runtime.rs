//! Identify the native binaries under test. `harness` owns every Runtime launch.

use crate::build::{lane, offline_build};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug)]
pub struct BinaryUnderTest {
    pub binary: PathBuf,
    pub sha256: String,
}

/// Names a Runtime binary for the suite to launch instead of building one.
pub const RUNTIME_BINARY: &str = "AGENT_CONFORMANCE_RUNTIME_BINARY";

/// Cache failures too: each test process attempts at most one Runtime build.
/// The caller holds the repository's shared heavy-build lease.
///
/// With `AGENT_CONFORMANCE_RUNTIME_BINARY` set, the suite launches that binary
/// where it is and builds no Runtime; unset, it builds the checkout's Runtime
/// as before. Only the Runtime is given: the localhost provider, the probe and
/// every Home the Runtime runs in still come from this checkout, so a given
/// Runtime never reads its own installation's data folder.
pub fn runtime_under_test() -> Result<&'static BinaryUnderTest, &'static str> {
    static RUNTIME: OnceLock<Result<BinaryUnderTest, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| match std::env::var_os(RUNTIME_BINARY) {
            Some(given) => given_native(Path::new(&given), "elastos").inspect(|given| {
                // Printed here, not in `given_native`: a version identity line
                // enters the receipt, so only the Runtime the suite launches
                // may print one.
                println!("elastos given, not built");
                crate::identity::Observation::Native {
                    role: "elastos".into(),
                    sha256: given.sha256.clone(),
                }
                .emit();
            }),
            None => build_native("elastos-server", "elastos"),
        })
        .as_ref()
        .map_err(String::as_str)
}

/// Share the Runtime build settings and cache the provider result, including failure.
pub fn localhost_provider_under_test() -> Result<&'static BinaryUnderTest, &'static str> {
    static PROVIDER: OnceLock<Result<BinaryUnderTest, String>> = OnceLock::new();
    PROVIDER
        .get_or_init(|| build_native("localhost-provider", "localhost-provider"))
        .as_ref()
        .map_err(String::as_str)
}

fn build_native(package: &str, name: &str) -> Result<BinaryUnderTest, String> {
    let target = lane().join("target/runtime");
    let started = Instant::now();
    let output = offline_build("cargo", &target)
        .map_err(|error| format!("prepare {name} build: {error}"))?
        .args([
            "build",
            "--locked",
            "--offline",
            "--manifest-path",
            "elastos/Cargo.toml",
            "-p",
            package,
            "--bin",
            name,
        ])
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .output()
        .map_err(|error| format!("start {name} build: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{name} build failed ({}):\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let binary = target.join("debug").join(name);
    let sha256 = sha256_file(&binary)?;
    println!(
        "{name} build finished in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    crate::identity::Observation::Native {
        role: name.into(),
        sha256: sha256.clone(),
    }
    .emit();
    Ok(BinaryUnderTest { binary, sha256 })
}

/// Identify a binary that was given, not built. It is hashed where it is and
/// never copied or changed, and nothing is printed.
fn given_native(binary: &Path, name: &str) -> Result<BinaryUnderTest, String> {
    if !binary.is_absolute() {
        return Err(format!("given {name} binary needs an absolute path"));
    }
    if !binary.is_file() {
        return Err(format!("given {name} binary is not a file"));
    }
    let sha256 = sha256_file(binary)?;
    Ok(BinaryUnderTest {
        binary: binary.to_path_buf(),
        sha256,
    })
}

/// Hash built and installed copies through the same std-only path.
pub fn sha256_file(path: &Path) -> Result<String, String> {
    // macOS supplies shasum. Hash the bytes through stdin, without running the
    // binary or adding a crate dependency to this std-only harness.
    let output = Command::new("/usr/bin/shasum")
        .args(["-a", "256"])
        .stdin(File::open(path).map_err(|error| format!("open binary for SHA-256: {error}"))?)
        .output()
        .map_err(|error| format!("hash binary: {error}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let hash = text.split_whitespace().next().unwrap_or("");
    if !output.status.success() || hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "binary SHA-256 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(hash.to_owned())
}

#[cfg(test)]
mod tests {
    use super::given_native;
    use crate::harness::ThrowawayHome;

    #[test]
    fn given_runtime_is_identified_where_it_is() {
        let home = ThrowawayHome::new().unwrap();
        let binary = home.root().join("given-elastos");
        std::fs::write(&binary, b"given runtime").unwrap();
        let given = given_native(&binary, "elastos").unwrap();
        assert_eq!(given.binary, binary);
        assert_eq!(given.sha256, crate::identity::sha256(b"given runtime"));
        assert_eq!(
            given_native(std::path::Path::new("given-elastos"), "elastos").unwrap_err(),
            "given elastos binary needs an absolute path"
        );
        assert_eq!(
            given_native(&home.root().join("absent"), "elastos").unwrap_err(),
            "given elastos binary is not a file"
        );
        home.finish().unwrap();
    }
}
