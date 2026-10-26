//! Every byte of a bundle is its identity (PRINCIPLES 13): one byte changed
//! in the manifest, in any payload file or in agent-host's `asks.json`, or a
//! file added or removed, changes the lab CID. Each test names a bundle
//! before and after one change, so a byte the name leaves out cannot hide
//! behind a pin that differs anyway; then `check_name` refuses the old name
//! with both values.
mod common;

use std::fs;
use std::path::Path;

use capsule_identity::MANIFEST_FILE;
use common::*;
use elastos_common::CapsuleManifest;

/// The offset of the first character of the JSON string value `value` in
/// `json`: inside the quotes, so a letter changed there keeps the file valid
/// JSON. The quoted value occurs exactly once.
fn inside_string_value(json: &[u8], value: &str) -> usize {
    let quoted = format!("\"{value}\"");
    let text = std::str::from_utf8(json).expect("UTF-8 JSON");
    assert_eq!(text.matches(&quoted).count(), 1, "{quoted}");
    text.find(&quoted).expect("the quoted value") + 1
}

/// Change the one byte at `at` in the bundle file `file` by flipping its
/// ASCII case bit, and return the file's new bytes. They differ from the old
/// in exactly that byte.
fn change_one_byte(bundle: &Path, file: &str, at: usize) -> Vec<u8> {
    let path = bundle.join(file);
    let old = fs::read(&path).expect("read the bundle file");
    let mut new = old.clone();
    new[at] ^= 0x20;
    fs::write(&path, &new).expect("write the bundle file");
    let differing = old.iter().zip(&new).filter(|(a, b)| a != b).count();
    assert_eq!((differing, new.len()), (1, old.len()), "{file}");
    new
}

#[test]
fn one_byte_change_in_the_manifest_changes_the_lab_cid() {
    let bundle = assemble(&WEB_APP);
    let before = named(bundle.path());
    let manifest = read_fixture(&WEB_APP, MANIFEST_FILE);
    let at = inside_string_value(&manifest, "Show example information");
    let changed = change_one_byte(bundle.path(), MANIFEST_FILE, at);
    // Still a manifest the Runtime's own two checks accept, so the walk
    // names it rather than refusing it.
    let parsed: CapsuleManifest =
        serde_json::from_slice(&changed).unwrap_or_else(|reason| panic!("parse: {reason}"));
    parsed
        .validate()
        .unwrap_or_else(|reason| panic!("validate: {reason}"));
    let after = named(bundle.path());

    assert_ne!(
        after, before,
        "a one-byte change in capsule.json did not change the lab CID"
    );
    assert_eq!(before.to_string(), WEB_APP_LAB_CID);
    assert_name_mismatch(bundle.path(), WEB_APP_LAB_CID, after);
}

#[test]
fn one_byte_change_in_any_payload_file_changes_the_lab_cid() {
    // Every web-app file but the manifest, in turn. browser/app.js is not
    // the entrypoint, and its bytes count the same as the entrypoint's.
    let manifest: CapsuleManifest =
        serde_json::from_slice(&read_fixture(&WEB_APP, MANIFEST_FILE)).expect("web-app manifest");
    let payload: Vec<&str> = WEB_APP
        .files
        .iter()
        .copied()
        .filter(|file| *file != MANIFEST_FILE)
        .collect();
    assert!(payload.contains(&"browser/app.js"), "{payload:?}");
    assert_ne!(manifest.entrypoint, "browser/app.js");

    let mut befores = Vec::new();
    for file in payload {
        let bundle = assemble(&WEB_APP);
        let before = named(bundle.path());
        let middle = read_fixture(&WEB_APP, file).len() / 2;
        change_one_byte(bundle.path(), file, middle);
        let after = named(bundle.path());

        assert_ne!(
            after, before,
            "a one-byte change in {file} did not change the lab CID"
        );
        assert_name_mismatch(bundle.path(), &before.to_string(), after);
        befores.push(before);
    }
    // Checked after every file, so a file the name leaves out fails on its
    // own change above, never first on a pin.
    for before in befores {
        assert_eq!(before.to_string(), WEB_APP_LAB_CID);
    }
}

#[test]
fn adding_or_removing_a_payload_file_changes_the_lab_cid() {
    let changes: [(&str, fn(&Path)); 3] = [
        ("adding browser/app.js.map", |bundle| {
            write_file(bundle, "browser/app.js.map", b"{}\n")
        }),
        ("adding an empty notes.txt", |bundle| {
            write_file(bundle, "notes.txt", b"")
        }),
        ("removing browser/app.js", |bundle| {
            fs::remove_file(bundle.join("browser/app.js")).expect("remove browser/app.js")
        }),
    ];
    let mut befores = Vec::new();
    for (change, make) in changes {
        let bundle = assemble(&WEB_APP);
        let before = named(bundle.path());
        make(bundle.path());
        let after = named(bundle.path());

        assert_ne!(after, before, "{change} did not change the lab CID");
        assert_name_mismatch(bundle.path(), &before.to_string(), after);
        befores.push(before);
    }
    // Checked after every change, as in the payload test above.
    for before in befores {
        assert_eq!(before.to_string(), WEB_APP_LAB_CID);
    }
}

#[test]
fn one_byte_change_in_asks_json_changes_the_lab_cid() {
    // M1 check B2: the asks a capsule declares are inside its name. The lab
    // never parses asks.json; to the lab CID it is one more payload file.
    let bundle = assemble(&AGENT_HOST);
    let before = named(bundle.path());
    let asks = read_fixture(&AGENT_HOST, "asks.json");
    let at = inside_string_value(&asks, "Models/");
    let changed = change_one_byte(bundle.path(), "asks.json", at);
    serde_json::from_slice::<serde_json::Value>(&changed).expect("asks.json is still JSON");
    let after = named(bundle.path());

    assert_ne!(
        after, before,
        "a one-byte change in asks.json did not change the lab CID"
    );
    assert_eq!(before.to_string(), AGENT_HOST_LAB_CID);
    assert_ne!(after.to_string(), AGENT_HOST_LAB_CID);
    assert_name_mismatch(bundle.path(), AGENT_HOST_LAB_CID, after);
}
