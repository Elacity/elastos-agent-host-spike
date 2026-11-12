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

/// Printed, with both hashes, when a given Runtime is refused at a launch.
pub const CHANGED: &str = "given Runtime changed: ";

/// The harness calls this immediately before it starts any program. A given
/// Runtime is hashed again here, once per launch, and is refused unless it
/// still has the bytes first recorded for it, so a file replaced after that
/// first hash is not launched under the recorded hash. The differing hash is
/// also printed as an identity line, so the receipt records the conflict even
/// if a caller drops the error.
///
/// What this does not show: a replacement made after this hash and before the
/// operating system starts the process, or what a started Runtime then starts
/// by itself.
pub fn unchanged_before_launch(program: &Path) -> Result<(), &'static str> {
    let Some(given) = std::env::var_os(RUNTIME_BINARY) else {
        return Ok(());
    };
    if program != Path::new(&given) {
        return Ok(());
    }
    let first = runtime_under_test()?;
    let Ok(now) = sha256_file(program) else {
        println!("{CHANGED}it could not be hashed again before a launch; not launched");
        return Err("given Runtime binary could not be hashed again before a launch; not launched");
    };
    if now == first.sha256 {
        return Ok(());
    }
    println!(
        "{CHANGED}first hashed {}, {now} immediately before a launch; not launched",
        first.sha256
    );
    crate::identity::Observation::Native {
        role: "elastos".into(),
        sha256: now,
    }
    .emit();
    Err("given Runtime binary changed after it was first hashed; not launched")
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
    // Hash the bytes through stdin, without running the binary or adding a
    // crate dependency to this std-only harness. A given Runtime is hashed
    // before every launch, inside the time bounds of the tests that launch it,
    // so the system's own sha256sum is used where there is one: it is several
    // times faster than shasum, which macOS and Linux both supply and which
    // stays the fallback. Both print the hash first.
    let (tool, arguments): (&str, &[&str]) = ["/sbin/sha256sum", "/usr/bin/sha256sum"]
        .into_iter()
        .find(|tool| Path::new(tool).is_file())
        .map_or(("/usr/bin/shasum", &["-a", "256"]), |tool| (tool, &[]));
    let output = Command::new(tool)
        .args(arguments)
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
    use super::{given_native, runtime_under_test, RUNTIME_BINARY};
    use crate::harness::ThrowawayHome;
    use crate::identity::{sha256, Observation, PREFIX};
    use std::path::{Path, PathBuf};

    /// Set in the second process of a test that needs one.
    const SECOND: &str = "AGENT_CONFORMANCE_TEST_SECOND_PROCESS";

    /// The given binary, when this is the second process of a test.
    fn in_second_process() -> Option<PathBuf> {
        std::env::var_os(SECOND)?;
        std::env::var_os(RUNTIME_BINARY).map(PathBuf::from)
    }

    /// Runs one test of this file again in a second process with `given` as the
    /// given Runtime, and returns what it printed. A second process is needed
    /// because the given Runtime is read once per process, and because a test
    /// cannot read what it printed itself. Its PATH is `empty`, a folder with
    /// no programs: nothing can be built there, so a test that expects the
    /// given binary fails at once if a build is tried instead.
    ///
    /// The stand-in's identity lines must never reach this run's own output as
    /// lines, so callers show the returned text escaped only.
    fn second_process(test: &str, given: &Path, empty: &Path) -> String {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                &format!("runtime::tests::{test}"),
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RUNTIME_BINARY, given)
            .env(SECOND, "1")
            .env("PATH", empty)
            .output()
            .unwrap();
        let printed = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success() && printed.contains("test result: ok. 1 passed"),
            "{printed:?} {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        printed
    }

    #[test]
    fn runtime_under_test_is_the_given_binary_when_one_is_named() {
        if let Some(given) = in_second_process() {
            let runtime = runtime_under_test().unwrap();
            assert_eq!(runtime.binary, given);
            assert_eq!(runtime.sha256, sha256(b"given runtime"));
            assert!(std::ptr::eq(runtime, runtime_under_test().unwrap()));
            return;
        }
        let home = ThrowawayHome::new().unwrap();
        let given = home.root().join("given-elastos");
        std::fs::write(&given, b"given runtime").unwrap();
        let printed = second_process(
            "runtime_under_test_is_the_given_binary_when_one_is_named",
            &given,
            home.temp(),
        );
        assert!(
            printed.contains("elastos given, not built\n"),
            "{printed:?}"
        );
        // One identity line, for the given bytes: this is the line the receipt
        // takes the Runtime's hash from.
        let identities: Vec<_> = printed
            .lines()
            .filter(|line| line.contains(PREFIX))
            .collect();
        let expected = Observation::Native {
            role: "elastos".into(),
            sha256: sha256(b"given runtime"),
        }
        .line();
        assert_eq!(identities, [expected], "{printed:?}");
        home.finish().unwrap();
    }

    #[test]
    fn identifying_a_given_binary_prints_no_identity_line() {
        if let Some(given) = in_second_process() {
            let identified = given_native(&given, "elastos").unwrap();
            assert_eq!(identified.sha256, sha256(b"some other file"));
            return;
        }
        // Every identity line in a run's output enters the receipt, so only the
        // Runtime the suite chose may print one. Identifying a file does not.
        let home = ThrowawayHome::new().unwrap();
        let given = home.root().join("given-elastos");
        std::fs::write(&given, b"some other file").unwrap();
        let printed = second_process(
            "identifying_a_given_binary_prints_no_identity_line",
            &given,
            home.temp(),
        );
        assert!(!printed.contains(PREFIX), "{printed:?}");
        assert!(
            !printed.contains(&sha256(b"some other file")),
            "{printed:?}"
        );
        home.finish().unwrap();
    }

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
