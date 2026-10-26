//! Three capsule kinds share the package rules: an app, a provider and a
//! model each get their name from `lab_cid` and their record from 011's one
//! record, the same way. A WASM app in this lab has one closure. Every
//! expected CID comes from the pins in `common`.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::{check_name, sign_package_record, verify_package_record, MANIFEST_FILE};
use common::*;
use elastos_common::CapsuleManifest;

/// The largest file any of the three fixtures may hold, in bytes.
const FILE_LIMIT: usize = 1024;
/// The largest lab stand-in the provider and model fixtures may hold, in
/// bytes: every file of theirs but the manifest.
const STAND_IN_LIMIT: usize = 64;

/// Words that mark a platform build: an architecture or an operating system.
/// A path part made of `-`- or `.`-separated words names a platform variant
/// when any word is one of these.
const PLATFORM_WORDS: [&str; 12] = [
    "aarch64", "arm64", "x86_64", "amd64", "i686", "riscv64", "darwin", "macos", "linux",
    "windows", "android", "ios",
];

/// Each fixture's bytes, path by path, as committed.
fn committed(fixture: &Fixture, bundle: &Path) -> Vec<(&'static str, Vec<u8>)> {
    fixture
        .files
        .iter()
        .map(|file| {
            let path = bundle.join(file);
            let bytes =
                fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            (*file, bytes)
        })
        .collect()
}

/// Flip one bit of the first byte of `file` in the bundle.
fn flip_first_byte(bundle: &Path, file: &str) {
    let mut bytes = fs::read(bundle.join(file)).expect("read the payload file");
    assert!(!bytes.is_empty(), "{file} has a byte to change");
    bytes[0] ^= 1;
    write_file(bundle, file, &bytes);
}

#[test]
fn three_kinds_share_the_package_rules() {
    for (fixture, pin, payload, stand_ins) in [
        (&WEB_APP, WEB_APP_LAB_CID, "browser/app.js", false),
        (&PROVIDER, PROVIDER_LAB_CID, "ipfs-provider", true),
        (&MODEL, MODEL_LAB_CID, "weights.gguf", true),
    ] {
        // Tiny: no file a chunker or a shard would split.
        for file in fixture.files {
            let size = read_fixture(fixture, file).len();
            let limit = if stand_ins && *file != MANIFEST_FILE {
                STAND_IN_LIMIT
            } else {
                FILE_LIMIT
            };
            assert!(
                size <= limit,
                "{}/{file} is {size} bytes, over {limit}",
                fixture.name
            );
        }

        let parent = temp_dir();
        let bundle = parent.path().join(fixture.name);
        assemble_at(fixture, &bundle);
        assert_eq!(named(&bundle).to_string(), pin, "{}", fixture.name);

        // The record is signed first, over the committed bytes, so its CID
        // is the pin. Signing and verifying leave the bundle and its parent
        // as they were.
        let bytes = committed(fixture, &bundle);
        let entries = listing(parent.path());
        let key = fresh_signing_key();
        let record = sign_package_record(&key, &bundle)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", fixture.name));
        assert_eq!(
            record.cid, pin,
            "{}: the record binds the pin",
            fixture.name
        );
        let accepted = [record.signer_did.clone()];
        verify_package_record(&bundle, &record, &accepted)
            .unwrap_or_else(|refusal| panic!("{}: {refusal}", fixture.name));
        assert_eq!(committed(fixture, &bundle), bytes, "{}", fixture.name);
        assert_eq!(listing(parent.path()), entries, "{}", fixture.name);

        // The folder's name is not the name: renamed, the CID and the record
        // both stand.
        let renamed = parent.path().join(format!("{}-renamed", fixture.name));
        fs::rename(&bundle, &renamed).expect("rename the bundle folder");
        assert_eq!(named(&renamed).to_string(), pin, "{} renamed", fixture.name);
        verify_package_record(&renamed, &record, &accepted)
            .unwrap_or_else(|refusal| panic!("{} renamed: {refusal}", fixture.name));

        // One byte is the name: the CID changes, and the old pin is refused
        // with both values.
        flip_first_byte(&renamed, payload);
        let changed = named(&renamed);
        assert_ne!(changed.to_string(), pin, "{}: {payload}", fixture.name);
        assert_name_mismatch(&renamed, pin, changed);
    }
}

/// Every path below `root`, folders included, relative to it and joined
/// with `/`, sorted. A link is listed and never followed.
fn tree(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut folders = vec![String::new()];
    while let Some(folder) = folders.pop() {
        for item in fs::read_dir(root.join(&folder)).expect("list a fixture folder") {
            let item = item.expect("read a fixture entry");
            let name = item.file_name().into_string().expect("UTF-8 fixture path");
            let path = if folder.is_empty() {
                name
            } else {
                format!("{folder}/{name}")
            };
            if item.file_type().expect("fixture entry type").is_dir() {
                folders.push(path.clone());
            }
            found.push(path);
        }
    }
    found.sort();
    found
}

/// The platform word in `path`, if one of its parts names a platform.
fn platform_word(path: &str) -> Option<&'static str> {
    path.split('/')
        .flat_map(|part| part.split(['-', '.']))
        .find_map(|word| {
            PLATFORM_WORDS
                .into_iter()
                .find(|platform| word.eq_ignore_ascii_case(platform))
        })
}

#[test]
fn a_wasm_app_has_one_closure() {
    // The rule's own words are read, so a check that never matches fails.
    assert_eq!(
        platform_word("aarch64-darwin/capsule.wasm"),
        Some("aarch64")
    );
    assert_eq!(platform_word("capsule-x86_64.wasm"), Some("x86_64"));
    assert_eq!(platform_word("browser/app.js"), None);

    for fixture in FIXTURES {
        let root = lane_dir().join("fixtures").join(fixture.name);
        let paths = tree(&root);
        let manifest: CapsuleManifest =
            serde_json::from_slice(&read_fixture(fixture, MANIFEST_FILE))
                .unwrap_or_else(|error| panic!("{}: {error}", fixture.name));
        let entrypoint = manifest.entrypoint.as_str();
        for path in paths.iter().map(String::as_str).chain([entrypoint]) {
            assert_eq!(
                platform_word(path),
                None,
                "{}: {path} names a platform variant",
                fixture.name
            );
        }

        // One manifest, at the root, and no second copy of the entrypoint.
        let manifests: Vec<&String> = paths
            .iter()
            .filter(|path| path.rsplit('/').next() == Some(MANIFEST_FILE))
            .collect();
        assert_eq!(manifests, [MANIFEST_FILE], "{}", fixture.name);
        let leaf = entrypoint.rsplit('/').next().expect("an entrypoint name");
        let copies = paths
            .iter()
            .filter(|path| path.rsplit('/').next() == Some(leaf))
            .count();
        assert!(copies <= 1, "{}: {copies} files named {leaf}", fixture.name);
    }

    // The WASM app: its module is built separately (wc-001's tools/build),
    // never committed, so the fixture holds the manifest alone.
    let root = lane_dir().join("fixtures").join(WC001_CORE.name);
    assert_eq!(tree(&root), [MANIFEST_FILE]);
    // The web-projection app holds one closure: exactly its listed files.
    let root = lane_dir().join("fixtures").join(WEB_APP.name);
    assert_eq!(
        tree(&root),
        [
            "browser",
            "browser/app.js",
            "browser/index.html",
            MANIFEST_FILE
        ]
    );
}
