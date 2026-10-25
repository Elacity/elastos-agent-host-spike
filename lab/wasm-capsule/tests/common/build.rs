//! Host-side helpers the named tests use to build the capsule reproducibly and
//! read back the receipt. Nothing here runs in the capsule; it only drives
//! `tools/build` and inspects its output.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The lane root: the directory holding `Cargo.toml`, `capsule/` and `tools/`.
/// For an integration test, `CARGO_MANIFEST_DIR` is that package root.
pub fn lane_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The source entries `tools/build` needs, never a `target/` directory.
const LANE_SOURCE_ENTRIES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "capsule",
    "tools",
];

/// A temporary directory removed when the handle is dropped, so a test leaves
/// nothing behind.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Make a fresh, uniquely named directory under the system temp dir.
    pub fn new(tag: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after the epoch")
            .as_nanos();
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "wc001-{tag}-{pid}-{nanos}-{unique}",
            pid = std::process::id(),
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Copy the lane's source (not its `target/`) into `dst`, which must exist.
pub fn copy_lane_source(src: &Path, dst: &Path) {
    for entry in LANE_SOURCE_ENTRIES {
        let from = src.join(entry);
        if !from.exists() {
            continue;
        }
        let status = Command::new("cp")
            .arg("-R")
            .arg(&from)
            .arg(dst.join(entry))
            .status()
            .expect("spawn cp");
        assert!(status.success(), "cp -R {} failed", from.display());
    }
}

/// Run `tools/build` for `lane`, writing the artifact and receipt into
/// `out_dir`. Panics with the captured output on failure, so a test sees why.
pub fn run_build(lane: &Path, out_dir: &Path) {
    let script = lane.join("tools").join("build");
    let output = Command::new("bash")
        .arg(&script)
        .arg(out_dir)
        .output()
        .expect("spawn tools/build");
    assert!(
        output.status.success(),
        "tools/build failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The lowercase hex sha256 of a file, from the system tool (the same one the
/// receipt records with). Independent of any Rust crate, so the lane's lockfile
/// stays free of the network.
pub fn sha256_file(path: &Path) -> String {
    for (bin, args) in [("sha256sum", &[][..]), ("shasum", &["-a", "256"][..])] {
        let Ok(output) = Command::new(bin).args(args).arg(path).output() else {
            continue;
        };
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            return text
                .split_whitespace()
                .next()
                .expect("sha256 tool printed a hash")
                .to_string();
        }
    }
    panic!("no sha256 tool (sha256sum or shasum) is available");
}

/// The build receipt, parsed from its `key: value` lines.
pub struct Receipt {
    fields: BTreeMap<String, String>,
}

impl Receipt {
    /// Read `OUT_DIR/receipt.txt`.
    pub fn read(out_dir: &Path) -> Receipt {
        let text = fs::read_to_string(out_dir.join("receipt.txt")).expect("read receipt.txt");
        Receipt::parse(&text)
    }

    pub fn parse(text: &str) -> Receipt {
        let mut fields = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once(':') {
                fields.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
        Receipt { fields }
    }

    /// The value for `key`, or a clear panic naming the missing field.
    pub fn get(&self, key: &str) -> &str {
        self.fields
            .get(key)
            .unwrap_or_else(|| panic!("receipt has no `{key}` field"))
    }
}

/// The exact compiler the lane builds with, as `rustc --version` reports it
/// from the lane root (so the lane's rust-toolchain.toml selects it, matching
/// what `tools/build` records).
pub fn rustc_version(lane: &Path) -> String {
    let output = Command::new("rustc")
        .arg("--version")
        .current_dir(lane)
        .output()
        .expect("spawn rustc --version");
    assert!(output.status.success(), "rustc --version failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
