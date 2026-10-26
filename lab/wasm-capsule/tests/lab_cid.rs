//! A lab bundle is named only by cc-capsule-identity's lab CID (PRINCIPLES P10,
//! P13, P15). The lane reaches it through one export,
//! `wasm_capsule_tools::bundle_identity`, and keeps no naming rule of its own.
//! The bundle's `capsule.json` is this capsule's own `elastos.capsule/v1`
//! manifest, read here only with the Runtime's `CapsuleManifest`.
//!
//! The tests live in the root package because the lane gate tests only that
//! package. They share one process, so none changes process-wide state.

mod common;

use common::build::{lane_dir, TempDir};
use elastos_common::{CapsuleManifest, CapsuleType};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use wasm_capsule_tools::{bundle_identity, CAPSULE_MANIFEST};

/// The smallest core Wasm module: the magic and version 1, no sections.
const MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// The lab CID of a bundle holding this capsule's manifest and [`MODULE`].
/// Computed once outside the lab code, with Python's `hashlib` over the
/// encoding in `lab/capsule-identity/README.md` ("The encoding"), and pinned.
/// It is also this lane's guard that the shared rule did not change under it.
const PINNED_LAB_CID: &str =
    "lab-cid:sha256:dd6673dafaf1a3180310d3207cccc59b3e414b584b2d93002bb81c8d293a3c47";

/// A bundle folder holding this capsule's manifest and [`MODULE`].
fn this_capsule_bundle(tmp: &TempDir) -> PathBuf {
    let bundle = tmp.path().join("bundle");
    fs::create_dir_all(&bundle).expect("create the bundle folder");
    fs::write(bundle.join("capsule.json"), CAPSULE_MANIFEST).expect("write capsule.json");
    fs::write(bundle.join("capsule.wasm"), MODULE).expect("write capsule.wasm");
    bundle
}

#[test]
fn lab_manifest_passes_runtime_validate() {
    let tmp = TempDir::new("lab-cid-manifest");
    let bundle = this_capsule_bundle(&tmp);
    if let Err(refusal) = bundle_identity(&bundle) {
        panic!("bundle_identity refused this capsule's bundle: {refusal}");
    }

    let manifest: CapsuleManifest = serde_json::from_slice(CAPSULE_MANIFEST)
        .unwrap_or_else(|error| panic!("CapsuleManifest refused capsule.json: {error}"));
    if let Err(error) = manifest.validate() {
        panic!("CapsuleManifest::validate() refused capsule.json: {error}");
    }
    assert_eq!(manifest.schema, "elastos.capsule/v1");
    assert_eq!(manifest.entrypoint, "capsule.wasm");
    assert!(
        matches!(manifest.capsule_type, CapsuleType::Wasm),
        "type is {:?}, not wasm",
        manifest.capsule_type
    );
    assert_eq!(manifest.role.as_str(), "app");
    assert_eq!(
        manifest.name,
        env!("CARGO_PKG_NAME"),
        "the manifest's name is not the root package's"
    );
    assert_eq!(
        manifest.version,
        env!("CARGO_PKG_VERSION"),
        "the manifest's version is not the root package's"
    );
}

#[test]
fn this_capsule_bundle_has_the_pinned_lab_cid() {
    let tmp = TempDir::new("lab-cid-pin");
    let bundle = this_capsule_bundle(&tmp);
    let named = bundle_identity(&bundle).unwrap_or_else(|refusal| {
        panic!("bundle_identity refused this capsule's bundle: {refusal}")
    });
    assert_eq!(named.to_string(), PINNED_LAB_CID);
}

/// The lane's own files, as git lists them (tracked, or new and not ignored),
/// relative to the lane. A listed file that is gone from the work tree is left
/// out: it holds nothing. So is the falsifier runner's backup
/// (`<file>.falsify-original`): a transient copy of a file that is already
/// listed under its own name.
fn lane_files(lane: &Path) -> Vec<(String, String)> {
    let output = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(lane)
        .output()
        .expect("run git ls-files in the lane");
    assert!(
        output.status.success(),
        "git ls-files failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let listing = String::from_utf8(output.stdout).expect("git lists UTF-8 paths");
    let mut files = Vec::new();
    for path in listing.lines() {
        if path.ends_with(".falsify-original") {
            continue;
        }
        match fs::read(lane.join(path)) {
            Ok(bytes) => files.push((path.to_owned(), String::from_utf8_lossy(&bytes).into())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read {path}: {error}"),
        }
    }
    files
}

#[test]
fn the_lane_keeps_no_bundle_name_rule_of_its_own() {
    // Built at run time, so this file does not match itself. The retired label
    // is checked in every listed file, docs included; the code names only
    // outside the files that may hold them as history.
    let retired_label = ["lab", "-sha", "256"].concat();
    let retired = [
        ["wc-003", ".lab-closure"].concat(),
        ["name", "_bundle"].concat(),
        ["lab", "_name"].concat(),
        ["canonical", "_closure"].concat(),
        ["read", "_bundle"].concat(),
        ["open", "_regular"].concat(),
    ];
    // The shared crate's naming functions, and the one line in the lane that
    // names one of them. wc-004's verifier and its tests import the shared
    // crate's checked bundle and name signature too; those name a bundle only
    // through `checked_bundle`, the same walk, never through these.
    let naming = [
        ["lab", "_cid"].concat(),
        ["lab", "_cid_observed"].concat(),
        ["checked_bundle", "_observed"].concat(),
        ["encode", "_entries"].concat(),
    ];
    let shared_crate = ["capsule", "_identity"].concat();
    let the_one_export = format!("pub use {shared_crate}::{} as bundle_identity;", naming[0]);

    let files = lane_files(&lane_dir());
    let mut found = Vec::new();
    let mut imports = Vec::new();
    for (path, text) in &files {
        let history = holds_history(path);
        for (number, line) in text.lines().enumerate() {
            if line.contains(retired_label.as_str()) {
                found.push(format!("{path}:{}: {retired_label}", number + 1));
            }
            if history {
                continue;
            }
            for needle in &retired {
                if line.contains(needle.as_str()) {
                    found.push(format!("{path}:{}: {needle}", number + 1));
                }
            }
            if naming.iter().any(|name| names_word(line, name)) {
                imports.push((path.as_str(), line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "the lane still holds a retired bundle name rule: {found:?}"
    );
    assert_eq!(
        imports,
        [("tools/src/lib.rs", the_one_export.as_str())],
        "the shared naming function must be imported only by the one export"
    );
}

/// Whether `path` may name retired code as history, so only the retired label
/// is checked in it: `audit/` (the cx-wasm-audit lane's), the docs and
/// `falsifiers.json`.
fn holds_history(path: &str) -> bool {
    path.starts_with("audit/") || path.ends_with(".md") || path == "falsifiers.json"
}

/// Whether `line` holds `word` as a whole identifier: no identifier character
/// just before or just after it.
fn names_word(line: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}
