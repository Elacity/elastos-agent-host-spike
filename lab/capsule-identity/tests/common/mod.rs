//! Shared test support: fixture bundles assembled in fresh temp dirs, the
//! pinned lab CIDs, a bounded call for bundles that hold a FIFO, observers
//! that change a bundle while it is named, and a driver for wc-001's own
//! build. Each test file includes this with `mod common;` and uses only part
//! of it, so dead-code warnings for the rest are silenced.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use capsule_identity::{lab_cid_observed, LabCid, Moment, Refusal};
use tempfile::TempDir;

/// The lab CIDs pinned for the committed fixtures. README.md lists the same
/// values.
pub const CONTENT_SAMPLE_LAB_CID: &str =
    "lab-cid:sha256:99cf6c7b9b4489f3a565cca47e1e30f2b4e7752bf0e8824806e7036f7a681d51";
pub const WEB_APP_LAB_CID: &str =
    "lab-cid:sha256:5559e5e3fe8f8e31006c035af0367d87810e214d987d1e8548d1bac03ca82066";

/// A committed fixture: its folder under `fixtures/` and the files of its
/// bundle.
pub struct Fixture {
    pub name: &'static str,
    pub files: &'static [&'static str],
}

pub const CONTENT_SAMPLE: Fixture = Fixture {
    name: "content-sample",
    files: &["capsule.json", "sample.example"],
};

/// Listed out of byte order on purpose: the encoder sorts.
pub const WEB_APP: Fixture = Fixture {
    name: "web-app",
    files: &["capsule.json", "browser/index.html", "browser/app.js"],
};

/// The manifest only. Its entrypoint `capsule.wasm` is built by wc-001's
/// `tools/build` in each test and is never committed.
pub const WC001_CORE: Fixture = Fixture {
    name: "wc001-core",
    files: &["capsule.json"],
};

pub const FIXTURES: [&Fixture; 3] = [&CONTENT_SAMPLE, &WEB_APP, &WC001_CORE];

/// This lane's root: the folder holding `Cargo.toml` and `fixtures/`.
pub fn lane_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The committed bytes of one fixture file.
pub fn read_fixture(fixture: &Fixture, file: &str) -> Vec<u8> {
    let path = lane_dir().join("fixtures").join(fixture.name).join(file);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// A fresh temp folder.
pub fn temp_dir() -> TempDir {
    tempfile::tempdir().expect("create a temp dir")
}

/// A fresh temp bundle holding exactly the fixture's committed files, so no
/// stray local file (such as `.DS_Store`) can reach a pinned value.
pub fn assemble(fixture: &Fixture) -> TempDir {
    let bundle = temp_dir();
    for file in fixture.files {
        write_file(bundle.path(), file, &read_fixture(fixture, file));
    }
    bundle
}

/// Write `bytes` at the bundle-relative `path` under `root`, making folders.
pub fn write_file(root: &Path, path: &str, bytes: &[u8]) {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).expect("create a folder");
    }
    fs::write(&target, bytes).expect("write a file");
}

/// Make a FIFO at `path` with the system's `mkfifo`.
pub fn make_fifo(path: &Path) {
    let status = Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo {} failed", path.display());
}

/// A temp folder outside any bundle that holds web-app's `browser/` file
/// names with other bytes, plus one extra file. A walk that follows a link,
/// or reads or lists by path after its check, meets these bytes or the
/// extra file instead of web-app's.
pub fn outside_browser() -> TempDir {
    let outside = temp_dir();
    write_file(outside.path(), "app.js", b"// outside the bundle\n");
    write_file(
        outside.path(),
        "index.html",
        b"<!-- outside the bundle -->\n",
    );
    write_file(outside.path(), "extra.js", b"// only outside the bundle\n");
    outside
}

/// The observer that only watches: the walk `lab_cid` runs.
pub fn unobserved(_: Moment, _: &str) {}

/// An observer that makes `change` once, when the walk reaches the entry
/// `path` at `moment`, and only watches otherwise.
pub fn at(
    moment: Moment,
    path: &'static str,
    change: impl FnOnce() + Send + 'static,
) -> impl FnMut(Moment, &str) + Send + 'static {
    let mut change = Some(change);
    move |now, seen| {
        if (now, seen) == (moment, path) {
            if let Some(change) = change.take() {
                change();
            }
        }
    }
}

/// How long a bounded call may take. Naming a small bundle takes
/// milliseconds.
pub const BOUND: Duration = Duration::from_secs(10);

/// `lab_cid_observed(bundle, observe)` on its own thread, waited for at most
/// [`BOUND`]. Opening a FIFO to read blocks until a writer comes, so a walk
/// that opens one before checking its type, or without the non-blocking
/// flag, fails here instead of hanging the run. With [`unobserved`] it runs
/// the walk `lab_cid` runs.
pub fn lab_cid_bounded(
    bundle: &Path,
    observe: impl FnMut(Moment, &str) + Send + 'static,
) -> Result<LabCid, Refusal> {
    let (sender, receiver) = mpsc::channel();
    let bundle = bundle.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(lab_cid_observed(&bundle, observe));
    });
    match receiver.recv_timeout(BOUND) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => panic!(
            "lab_cid did not return within {BOUND:?}: it opened an entry it should have refused"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("lab_cid panicked"),
    }
}

/// Build wc-001 with its own `tools/build` into `out_dir` (a temp dir; the
/// build writes nothing inside `lab/wasm-capsule/`) and return the module it
/// wrote there. A build that cannot run fails the test; it never skips.
pub fn wc001_module(out_dir: &Path) -> Vec<u8> {
    let script = lane_dir()
        .parent()
        .expect("lab/ holds this lane")
        .join("wasm-capsule/tools/build");
    let output = Command::new("bash")
        .arg(&script)
        .arg(out_dir)
        .output()
        .expect("spawn wc-001 tools/build");
    assert!(
        output.status.success(),
        "wc-001 tools/build failed ({}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    fs::read(out_dir.join("capsule.wasm")).expect("read wc-001 capsule.wasm")
}
