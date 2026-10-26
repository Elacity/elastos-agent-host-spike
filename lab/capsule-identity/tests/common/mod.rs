//! Shared test support: fixture bundles assembled in fresh temp dirs, the
//! pinned lab CIDs, a bounded call for bundles that hold a FIFO, observers
//! that change a bundle while it is named, a driver for wc-001's own build,
//! the library's code for tests that read it, the refusal asserts both
//! signature checks share, and the one key-material scan (kept here, a file
//! the falsifier runner restores after a killed run).
//! Each test file includes this with `mod common;` and uses only part of it,
//! so dead-code warnings for the rest are silenced.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use capsule_identity::{
    check_name, checked_bundle, checked_bundle_observed, lab_cid, lab_cid_observed, CheckedBundle,
    LabCid, Moment, Refusal,
};
use tempfile::TempDir;

/// The lab CIDs pinned for the committed fixtures. README.md lists the same
/// values.
pub const CONTENT_SAMPLE_LAB_CID: &str =
    "lab-cid:sha256:99cf6c7b9b4489f3a565cca47e1e30f2b4e7752bf0e8824806e7036f7a681d51";
pub const WEB_APP_LAB_CID: &str =
    "lab-cid:sha256:5559e5e3fe8f8e31006c035af0367d87810e214d987d1e8548d1bac03ca82066";
pub const AGENT_HOST_LAB_CID: &str =
    "lab-cid:sha256:43a918a50818e6f6ec81543a6dd423c796b03db028d0c7a4222f354c2afdc054";

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

/// The agent-host capsule's manifest and its declared asks, copied byte for
/// byte from `examples/agent-host/`. Its entrypoint module is build output
/// and is never committed, so it is not in the fixture.
pub const AGENT_HOST: Fixture = Fixture {
    name: "agent-host",
    files: &["capsule.json", "asks.json"],
};

pub const FIXTURES: [&Fixture; 4] = [&CONTENT_SAMPLE, &WEB_APP, &WC001_CORE, &AGENT_HOST];

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
    assemble_at(fixture, bundle.path());
    bundle
}

/// Write exactly the fixture's committed files into the bundle folder
/// `root`, making it, so a test can choose the folder's name and place.
pub fn assemble_at(fixture: &Fixture, root: &Path) {
    for file in fixture.files {
        write_file(root, file, &read_fixture(fixture, file));
    }
}

/// The lab CID of the bundle at `bundle`. A refusal fails the test with its
/// reason.
pub fn named(bundle: &Path) -> LabCid {
    lab_cid(bundle).unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

/// The checked bundle at `bundle`. A refusal fails the test with its reason.
pub fn checked(bundle: &Path) -> CheckedBundle {
    checked_bundle(bundle).unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

/// One fresh Ed25519 test key, drawn from the operating system's generator.
///
/// Every test key comes from here. Nothing writes it, prints it or keeps a
/// seed: the next call draws again, and two calls differ.
pub fn fresh_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// `check_name` refuses `claimed` for the bundle at `bundle`, whose bytes
/// name `actual`, and the refusal names both values.
pub fn assert_name_mismatch(bundle: &Path, claimed: &str, actual: LabCid) {
    assert_mismatch(check_name(bundle, claimed), claimed, actual);
}

/// A name check's answer refuses `claimed` for bytes that name `actual`, and
/// the refusal names both values. Both name checks are judged by this.
pub fn assert_mismatch(answer: Result<(), Refusal>, claimed: &str, actual: LabCid) {
    let refusal = answer.expect_err("a lab CID the bundle's bytes do not give must be refused");
    assert_eq!(
        refusal,
        Refusal::NameMismatch {
            actual,
            claimed: claimed.to_owned()
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("bundle bytes name {actual}; the claim is {claimed}")
    );
}

/// The refusal is the decoder's: `did` is not a canonical Ed25519 `did:key`,
/// with `elastos_identity::decode_did_key`'s own text.
pub fn assert_malformed(refusal: Refusal, did: &str) {
    let reason = elastos_identity::decode_did_key(did)
        .expect_err("this DID is not canonical")
        .to_string();
    assert_eq!(
        refusal,
        Refusal::MalformedSignerDid {
            did: did.to_owned(),
            reason: reason.clone(),
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signer DID {did} is not a canonical Ed25519 did:key: {reason}")
    );
}

/// The refusal is the accepted-list check's, for `did`.
pub fn assert_not_accepted(refusal: Refusal, did: &str) {
    assert_eq!(
        refusal,
        Refusal::SignerNotAccepted {
            did: did.to_owned()
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signer {did} is not in the accepted list")
    );
}

/// The refusal is the Ed25519 check's, for `did` over `name`.
pub fn assert_does_not_verify(refusal: Refusal, did: &str, name: &str) {
    assert_eq!(
        refusal,
        Refusal::SignatureDoesNotVerify {
            did: did.to_owned(),
            name: name.to_owned(),
        }
    );
    assert_eq!(
        refusal.to_string(),
        format!("signature by {did} does not verify over {name}")
    );
}

/// A wrapper's answer is the walk's own refusal `own`, unchanged.
pub fn assert_same_refusal(got: Result<(), Refusal>, own: &Refusal) {
    let got = got.expect_err("the wrapper must refuse what the walk refuses");
    assert_eq!(&got, own, "the wrapper changed the walk's refusal");
    assert_eq!(got.to_string(), own.to_string());
}

/// Flip one bit of web-app's `browser/app.js` on disk.
pub fn flip_web_app_js(bundle: &Path) {
    let mut bytes = fs::read(bundle.join("browser/app.js")).expect("read browser/app.js");
    assert!(!bytes.is_empty(), "browser/app.js has a byte to change");
    bytes[0] ^= 1;
    write_file(bundle, "browser/app.js", &bytes);
}

/// Three bundles the walk refuses, each for its own reason: no manifest, a
/// manifest the Runtime's check refuses, and a payload that is a link.
pub fn walk_refused_bundles() -> [TempDir; 3] {
    let no_manifest = temp_dir();
    write_file(
        no_manifest.path(),
        "sample.example",
        &read_fixture(&CONTENT_SAMPLE, "sample.example"),
    );

    let invalid = assemble(&CONTENT_SAMPLE);
    let manifest = String::from_utf8(read_fixture(&CONTENT_SAMPLE, "capsule.json"))
        .expect("UTF-8 manifest")
        .replacen("elastos.capsule/v1", "elastos.capsule/v2", 1);
    write_file(invalid.path(), "capsule.json", manifest.as_bytes());

    let linked = assemble(&WEB_APP);
    std::os::unix::fs::symlink("app.js", linked.path().join("browser/alias.js"))
        .expect("link a payload");

    [no_manifest, invalid, linked]
}

/// The names in the folder `parent`, sorted.
pub fn listing(parent: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(parent)
        .unwrap_or_else(|error| panic!("list {}: {error}", parent.display()))
        .map(|entry| {
            entry
                .expect("read a folder entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The library's code without its comment lines, so a test that reads the
/// code is never misled by a comment that names a call.
pub fn library_code() -> String {
    include_str!("../../src/lib.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One item of `code` (from [`library_code`]): the text from `head`, which
/// must be found exactly once, to the closing brace at `head`'s own indent.
/// So `pub fn name(` gives a function and `pub fn name(&self` a method.
pub fn library_item<'a>(code: &'a str, head: &str) -> &'a str {
    assert_eq!(code.matches(head).count(), 1, "the library holds {head:?}");
    let start = code.find(head).expect("found once");
    let line_start = code[..start].rfind('\n').map_or(0, |at| at + 1);
    let close = format!("\n{}}}", &code[line_start..start]);
    let end = code[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("{head:?} has no closing brace"));
    &code[start..start + end + close.len()]
}

/// The two ends of a PEM private-key header, built here so this source has
/// no header line of its own.
pub(super) fn pem_private_ends() -> (String, String) {
    (
        format!("-----{} ", "BEGIN"),
        format!("{}-----", "PRIVATE KEY"),
    )
}

pub(super) struct Filed<'a> {
    pub(super) name: &'a str,
    pub(super) bytes: &'a [u8],
}

pub(super) fn key_material_findings(files: &[Filed<'_>]) -> Vec<String> {
    let (header_start, header_end) = pem_private_ends();
    let mut found = Vec::new();
    for file in files {
        if file.name.ends_with(".key") || file.name.ends_with(".seed") {
            found.push(format!("name:{}", file.name));
        }
        if file.bytes.len() == 32 && std::str::from_utf8(file.bytes).is_err() {
            found.push(format!("raw-seed:{}", file.name));
        }
        // Invalid bytes elsewhere in a file must not hide its ASCII header markers.
        let text = String::from_utf8_lossy(file.bytes);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with(&header_start) && trimmed.ends_with(&header_end) {
                found.push(format!("header:{}:{index}", file.name));
            }
        }
    }
    found
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

/// `call(bundle)` on its own thread, waited for at most [`BOUND`]. Opening a
/// FIFO to read blocks until a writer comes, so a walk that opens one before
/// checking its type, or without the non-blocking flag, fails here instead
/// of hanging the run. `what` names the call when it fails.
pub fn bounded<T: Send + 'static>(
    what: &str,
    bundle: &Path,
    call: impl FnOnce(&Path) -> Result<T, Refusal> + Send + 'static,
) -> Result<T, Refusal> {
    let (sender, receiver) = mpsc::channel();
    let bundle = bundle.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(call(&bundle));
    });
    match receiver.recv_timeout(BOUND) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => panic!(
            "{what} did not return within {BOUND:?}: it opened an entry it should have refused"
        ),
        Err(RecvTimeoutError::Disconnected) => panic!("{what} panicked"),
    }
}

/// `lab_cid_observed(bundle, observe)`, [`bounded`]. With [`unobserved`] it
/// runs the walk `lab_cid` runs.
pub fn lab_cid_bounded(
    bundle: &Path,
    observe: impl FnMut(Moment, &str) + Send + 'static,
) -> Result<LabCid, Refusal> {
    bounded("lab_cid", bundle, move |bundle| {
        lab_cid_observed(bundle, observe)
    })
}

/// `checked_bundle_observed(bundle, observe)`, [`bounded`]. With
/// [`unobserved`] it runs the walk `checked_bundle` runs.
pub fn checked_bundle_bounded(
    bundle: &Path,
    observe: impl FnMut(Moment, &str) + Send + 'static,
) -> Result<CheckedBundle, Refusal> {
    bounded("checked_bundle", bundle, move |bundle| {
        checked_bundle_observed(bundle, observe)
    })
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
