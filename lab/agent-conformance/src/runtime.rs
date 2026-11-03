//! Identify the checkout's native binaries. `harness` owns every Runtime launch.

use crate::build::{lane, offline_build};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug)]
pub struct BinaryUnderTest {
    binary: PathBuf,
    pub sha256: String,
}

impl BinaryUnderTest {
    /// Recheck the recorded build identity immediately before a path-based use.
    pub fn verified_path(&self) -> Result<&Path, String> {
        if sha256_file(&self.binary)? != self.sha256 {
            return Err("native binary SHA-256 differs from recorded build".into());
        }
        Ok(&self.binary)
    }
}

/// Cache failures too: each test process attempts at most one Runtime build.
/// The caller holds the repository's shared heavy-build lease.
pub fn runtime_under_test() -> Result<&'static BinaryUnderTest, &'static str> {
    static RUNTIME: OnceLock<Result<BinaryUnderTest, String>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| build_native("elastos-server", "elastos"))
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
    use super::*;
    use crate::harness::{Launch, RunningInstances, ThrowawayHome};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    const ORIGINAL: &[u8] = b"#!/bin/sh\nprintf original > \"$HOME/../marker\"\nprintf ready > \"$HOME/../ready\"\nif [ \"$2\" = managed ]; then exec /bin/sleep 20; fi\n";
    const CHANGED: &[u8] = b"#!/bin/sh\nprintf replaced > \"$HOME/../marker\"\nprintf ready > \"$HOME/../ready\"\nif [ \"$2\" = managed ]; then exec /bin/sleep 20; fi\n";
    const BOUND: Duration = Duration::from_secs(2);

    #[derive(Clone, Copy, Debug)]
    enum LaunchForm {
        Bounded,
        Managed,
        Parallel,
    }

    fn launch_fixture(
        native: &BinaryUnderTest,
        home: &ThrowawayHome,
        form: LaunchForm,
    ) -> Result<(), String> {
        match form {
            LaunchForm::Bounded => {
                let output = home.launch(native.verified_path()?, &["run"], BOUND)?;
                if !output.status.success() {
                    return Err("bounded fixture exited unsuccessfully".into());
                }
            }
            LaunchForm::Managed => {
                let mut child = home.start(native.verified_path()?, &["run", "managed"])?;
                let pgid = child.pgid();
                let started = Instant::now();
                let ready = loop {
                    if fs::read(home.root().join("ready")).is_ok_and(|bytes| bytes == b"ready") {
                        break true;
                    }
                    if started.elapsed() >= BOUND {
                        break false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                };
                // Settle the owned group before any behavior assertion, also
                // when a compiling plant admits the replacement executable.
                child.stop()?;
                drop(child);
                if home.group_is_alive(pgid)? {
                    return Err("managed fixture group did not drain".into());
                }
                if !ready {
                    return Err("managed fixture readiness exceeded its bound".into());
                }
            }
            LaunchForm::Parallel => {
                let launches = [0, 1]
                    .map(|_| {
                        Ok(Launch {
                            home,
                            program: native.verified_path()?,
                            args: vec!["run"],
                        })
                    })
                    .into_iter()
                    .collect::<Result<Vec<_>, String>>()?;
                let completions = RunningInstances::start(&launches, None)?.collect(BOUND)?;
                if completions.len() != 2
                    || completions.iter().any(|item| !item.output.status.success())
                {
                    return Err("parallel fixtures did not both exit successfully".into());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn native_identity_refuses_changed_or_missing_bytes() {
        assert_eq!(ORIGINAL.len(), CHANGED.len(), "same-length fixture change");
        for form in [
            LaunchForm::Bounded,
            LaunchForm::Managed,
            LaunchForm::Parallel,
        ] {
            let home = ThrowawayHome::new().unwrap();
            let binary = home.root().join("native-fixture");
            fs::write(&binary, ORIGINAL).unwrap();
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
            // Independent fixed-byte digest; synthetic identities emit no live
            // native observation and build neither Runtime nor probe.
            let native = BinaryUnderTest {
                binary: binary.clone(),
                sha256: format!("{:x}", Sha256::digest(ORIGINAL)),
            };
            let admitted_starts = if matches!(form, LaunchForm::Parallel) {
                2
            } else {
                1
            };
            for (state, bytes) in [
                ("original", Some(ORIGINAL)),
                ("changed", Some(CHANGED)),
                ("restored", Some(ORIGINAL)),
                ("missing", None),
            ] {
                let marker = home.root().join("marker");
                let ready = home.root().join("ready");
                for path in [&marker, &ready] {
                    if path.exists() {
                        fs::remove_file(path).unwrap();
                    }
                }
                if let Some(bytes) = bytes {
                    fs::write(&binary, bytes).unwrap();
                } else {
                    fs::remove_file(&binary).unwrap();
                }
                let before = home.run_starts();
                let result = launch_fixture(&native, &home, form);
                if matches!(state, "original" | "restored") {
                    assert_eq!(result, Ok(()), "{form:?} {state}: launch");
                    assert_eq!(
                        fs::read(&ready).unwrap(),
                        b"ready",
                        "{form:?} {state}: ready"
                    );
                    assert_eq!(
                        fs::read(&marker).unwrap(),
                        b"original",
                        "{form:?} {state}: marker"
                    );
                    assert_eq!(
                        home.run_starts(),
                        before + admitted_starts,
                        "{form:?} {state}: starts"
                    );
                } else {
                    assert!(
                        !marker.exists(),
                        "{form:?} {state}: refused bytes reached the marker"
                    );
                    assert_eq!(
                        home.run_starts(),
                        before,
                        "{form:?} {state}: refusal started a child"
                    );
                    if state == "changed" {
                        assert_eq!(
                            result,
                            Err("native binary SHA-256 differs from recorded build".into()),
                            "{form:?} {state}: exact mismatch cause"
                        );
                    } else {
                        assert!(
                            result.is_err_and(
                                |reason| reason.starts_with("open binary for SHA-256: ")
                            ),
                            "{form:?} {state}: preserve open-for-SHA-256 cause"
                        );
                    }
                }
                assert_eq!(
                    native.sha256,
                    format!("{:x}", Sha256::digest(ORIGINAL)),
                    "{form:?} {state}: recorded identity stays fixed"
                );
            }
            home.finish().unwrap();
        }
    }
}
