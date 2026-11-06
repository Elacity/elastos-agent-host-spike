//! Identify the checkout's native binaries. `harness` owns every Runtime launch.

use crate::build::{lane, offline_build};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::Instant;

#[derive(Debug)]
pub struct BinaryUnderTest {
    pub binary: PathBuf,
    pub sha256: String,
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
    sha256_output(output)
}

fn sha256_output(output: Output) -> Result<String, String> {
    let text = String::from_utf8_lossy(&output.stdout);
    let hash = text.split_whitespace().next().unwrap_or("");
    if !output.status.success() || hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(format!(
            "binary SHA-256 failed ({}): stdout={:?}; stderr={:?}",
            output.status,
            text,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(hash.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{harness::ThrowawayHome, identity::sha256};
    use std::fs;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn native_hash_refusal_keeps_tool_result() {
        const HASH: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let ordinary = format!("{HASH}  -\n");
        let non_hex = "g".repeat(64);
        let long = "a".repeat(65);
        let cases = [
            (
                "failed exit with digest",
                7,
                ordinary.as_bytes(),
                b"fixture failure\n".as_slice(),
                format!("\"{HASH}  -\\n\""),
                "\"fixture failure\\n\"",
            ),
            (
                "failed exit with empty streams",
                9,
                b"",
                b"",
                "\"\"".into(),
                "\"\"",
            ),
            ("empty digest", 0, b"", b"", "\"\"".into(), "\"\""),
            (
                "short digest",
                0,
                b"abc  -\n",
                b"",
                "\"abc  -\\n\"".into(),
                "\"\"",
            ),
            (
                "long digest",
                0,
                long.as_bytes(),
                b"",
                format!("\"{long}\""),
                "\"\"",
            ),
            (
                "non-hex digest",
                0,
                non_hex.as_bytes(),
                b"",
                format!("\"{non_hex}\""),
                "\"\"",
            ),
            (
                "lossy streams and escaped lines",
                0,
                b"\xff\nfixture stdout\n",
                b"\xfe\nfixture \"stderr\"\\\n",
                "\"�\\nfixture stdout\\n\"".into(),
                "\"�\\nfixture \\\"stderr\\\"\\\\\\n\"",
            ),
        ];
        for (label, code, stdout, stderr, escaped_stdout, escaped_stderr) in cases {
            let status = ExitStatus::from_raw(code << 8);
            let expected = format!(
                "binary SHA-256 failed ({status}): stdout={escaped_stdout}; stderr={escaped_stderr}"
            );
            let result = sha256_output(Output {
                status,
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
            });
            let Err(error) = result else {
                panic!("{label}: tool result must be refused without a digest");
            };
            assert!(
                error == expected,
                "{label}: refusal must retain status and both escaped streams"
            );
            assert!(
                !error.contains('\n'),
                "{label}: refusal must stay on one diagnostic line"
            );
            let recovered = sha256_output(Output {
                status: ExitStatus::from_raw(0),
                stdout: ordinary.as_bytes().to_vec(),
                stderr: Vec::new(),
            });
            assert!(
                recovered.as_deref() == Ok(HASH),
                "{label}: ordinary result must recover its unchanged first token"
            );
        }
    }

    #[test]
    fn native_hash_reads_exact_fixture_bytes() {
        let home = ThrowawayHome::new().expect("create hash fixture Home");
        home.guard(home.home(), home.data())
            .expect("guard hash fixture Home");
        let path = home.home().join("native-hash-fixture");
        let original = b"native hash fixture: original\n\0\xff";
        let changed = b"native hash fixture: changed\n\0\xfe";
        let original_hash = sha256(original);
        let changed_hash = sha256(changed);
        assert_ne!(original_hash, changed_hash, "fixture digests must differ");
        fs::write(&path, original).expect("write original fixture bytes");
        assert_eq!(
            sha256_file(&path).expect("hash original fixture bytes"),
            original_hash,
            "real tool must hash the exact original bytes"
        );
        fs::write(&path, changed).expect("write changed fixture bytes");
        assert_eq!(
            sha256_file(&path).expect("hash changed fixture bytes"),
            changed_hash,
            "real tool must hash the exact changed bytes"
        );
        fs::remove_file(&path).expect("remove hash fixture");
        let missing = sha256_file(&path).expect_err("missing fixture must refuse identity");
        assert!(
            missing.starts_with("open binary for SHA-256: "),
            "missing fixture must retain the open failure cause"
        );
        fs::write(&path, original).expect("restore original fixture bytes");
        assert_eq!(
            sha256_file(&path).expect("hash restored fixture bytes"),
            original_hash,
            "restored bytes must recover the original digest"
        );
        home.finish().expect("remove passed hash fixture Home");
    }
}
