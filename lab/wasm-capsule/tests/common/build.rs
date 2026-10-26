//! Host-side helpers the named tests use to build the capsule reproducibly and
//! read back the receipt. Nothing here runs in the capsule; it only drives
//! `tools/build` and inspects its output.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The lane root: the directory holding `Cargo.toml`, `capsule/`, `audit/` and
/// `tools/`. For an integration test, `CARGO_MANIFEST_DIR` is that package root.
pub fn lane_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The source entries `tools/build` needs, never a `target/` directory.
/// `audit` is a workspace member: Cargo loads every member's manifest, so the
/// build fails without it even though `tools/build` compiles only `capsule`.
/// `capsule` carries the guest's source and its `capsule.json`.
const LANE_SOURCE_ENTRIES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "audit",
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

/// Where the lane sits under the repository root, and so under a copy's root.
const LANE_PATH: &str = "lab/wasm-capsule";

/// The folders outside the lane, relative to the repository root, that hold
/// the workspace's path dependencies: cc-capsule-identity's crate (from
/// `tools/`) and the Runtime's `elastos/` (from that crate and from the root
/// package's dev-dependency; Cargo also reads `elastos/Cargo.toml` for the
/// inherited `version.workspace`). Cargo loads each of their manifests to
/// resolve the one lockfile under `--locked`, even though `tools/build`
/// compiles only `capsule`.
const OUT_OF_LANE_PATH_DEPS: &[&str] = &["lab/capsule-identity", "elastos"];

/// Lay out a copy of the lane under `root`, which must exist, and return the
/// copied lane's folder, `root/lab/wasm-capsule`.
///
/// The lane's source (not its `target/`) is copied. Each folder in
/// [`OUT_OF_LANE_PATH_DEPS`] is reached through a symbolic link at the same
/// place under `root`, pointing at the real folder, so the copy's relative
/// path dependencies resolve. Cargo writes into neither folder: `tools/build`
/// sets its own `CARGO_TARGET_DIR`, and `--locked` writes no lockfile.
pub fn copy_lane_source(src: &Path, root: &Path) -> PathBuf {
    let lane = root.join(LANE_PATH);
    fs::create_dir_all(&lane).expect("create the lane folder in the copy");
    for entry in LANE_SOURCE_ENTRIES {
        let from = src.join(entry);
        if !from.exists() {
            continue;
        }
        let status = Command::new("cp")
            .arg("-R")
            .arg(&from)
            .arg(lane.join(entry))
            .status()
            .expect("spawn cp");
        assert!(status.success(), "cp -R {} failed", from.display());
    }
    let repo = src.join("../..");
    for dep in OUT_OF_LANE_PATH_DEPS {
        let link = root.join(dep);
        let parent = link.parent().expect("a path dependency has a parent");
        fs::create_dir_all(parent).expect("create a path dependency's parent in the copy");
        let target = fs::canonicalize(repo.join(dep))
            .unwrap_or_else(|error| panic!("find the path dependency {dep}: {error}"));
        std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|error| {
            panic!("link {} to {}: {error}", link.display(), target.display())
        });
    }
    lane
}

/// Run `tools/build` for `lane`, writing the artifact and receipt into
/// `out_dir`. Panics with the captured output on failure, so a test sees why.
pub fn run_build(lane: &Path, out_dir: &Path) {
    run_build_with_env(lane, out_dir, &[]);
}

/// Like [`run_build`], but with extra environment variables set on the build
/// process, used to pass an explicit `RUSTC` override. There is one build path
/// (PRINCIPLES P10): `run_build` is this with no extra environment.
pub fn run_build_with_env(lane: &Path, out_dir: &Path, env: &[(&str, &str)]) {
    let script = lane.join("tools").join("build");
    let mut command = Command::new("bash");
    command.arg(&script).arg(out_dir);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().expect("spawn tools/build");
    assert!(
        output.status.success(),
        "tools/build failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// The lowercase hex sha256 of a file, from the system tool: the same one
/// `tools/build` hashes the receipt's files with, so a receipt check compares
/// like with like. (The lab CID uses no system tool: cc-capsule-identity's
/// crate, which the tools crate re-exports, hashes it in-process.)
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

/// The exact compiler the lane builds with, as `--version` reports it. Honours
/// `$RUSTC` the way Cargo and `tools/build` do, so an explicit override is read
/// back from the same compiler, not a different `rustc` on PATH. With no
/// override it queries bare `rustc` from the lane root, so the lane's
/// rust-toolchain.toml selects the toolchain `tools/build` records.
pub fn rustc_version(lane: &Path) -> String {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let output = Command::new(&rustc)
        .arg("--version")
        .current_dir(lane)
        .output()
        .expect("spawn rustc --version");
    assert!(output.status.success(), "rustc --version failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}
