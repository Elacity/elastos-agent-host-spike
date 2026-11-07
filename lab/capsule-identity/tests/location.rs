//! Where a bundle lives is not its identity (PRINCIPLES 13): its folder's
//! name, its place, the URL it came from, the Store rows beside it, and its
//! files' times and modes never enter the lab CID. Each test names web-app
//! before and after one such change, and the two names must agree.
mod common;

use std::fs::{self, File, FileTimes, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use capsule_identity::check_name;
use common::*;
use serde_json::Value;

/// The `payload` object of the Runtime's own test row
/// `elastos/crates/elastos-server/tests/fixtures/capsule-record.json`, an
/// `elastos.capsule.record/v1` row, copied byte for byte. It is location
/// data beside a bundle only: the test adds no field to it and writes no lab
/// CID into it.
const CAPSULE_RECORD_ROW: &str = r#"{"capsule_version":null,"cid":"bafkreid46p2l75p47opclbxhh56vvq2355cg3ohh7ruypnygjuy2p52ibu","name":"system","platform":"*","release_path":"system.tar.gz","schema":"elastos.capsule.record/v1","sha256":"7cf3f4bff5fcfb9e2586e73f7d5ac35bef446db8e7fc6987b7064d31a7f7480d","signer_did":"did:key:z6MkhJwkQUmo5QaEyQ8pkuCcH9wpg2otnABouW3qpZV1F42W","size":37}"#;

/// One `external` platform row of the root `components.json`
/// (`external.shell.platforms.darwin-arm64`), copied with its values. It is
/// location data beside a bundle only, like the record row.
const COMPONENTS_ROW: &str = r#"{"cid":"","checksum":"sha256:dc364259e67025eec040cf8bccb59e80b687abfbe2f4f8ece1d6cd0fcac57c6d","size":0,"release_path":"shell-darwin-arm64","install_path":"bin/shell"}"#;

/// Write the location data into the listing folder that holds the bundle
/// folder, all outside the bundle: `source.url` with the URL the bundle came
/// from, and the two copied rows with `release_path` and the record's
/// `name` set to the given values.
fn write_location(listing: &Path, url: &str, release_path: &str, name: &str) {
    write_file(listing, "source.url", format!("{url}\n").as_bytes());
    let mut record: Value = serde_json::from_str(CAPSULE_RECORD_ROW).expect("the record row");
    record["release_path"] = release_path.into();
    record["name"] = name.into();
    let record = serde_json::to_vec(&record).expect("write the record row");
    write_file(listing, "capsule-record.json", &record);
    let mut row: Value = serde_json::from_str(COMPONENTS_ROW).expect("the components row");
    row["release_path"] = release_path.into();
    let row = serde_json::to_vec(&row).expect("write the components row");
    write_file(listing, "components-row.json", &row);
}

/// The bundle root and every folder and file below it, root first.
fn every_path(root: &Path) -> Vec<PathBuf> {
    let mut paths = vec![root.to_path_buf()];
    let mut next = 0;
    while next < paths.len() {
        if paths[next].is_dir() {
            let mut inside: Vec<PathBuf> = fs::read_dir(&paths[next])
                .expect("list a bundle folder")
                .map(|item| item.expect("read a bundle entry").path())
                .collect();
            inside.sort();
            paths.extend(inside);
        }
        next += 1;
    }
    paths
}

#[test]
fn renaming_the_bundle_folder_keeps_the_lab_cid() {
    let parent = temp_dir();
    let first = parent.path().join("web-app");
    assemble_at(&WEB_APP, &first);
    let before = named(&first);

    let renamed = parent.path().join("example-web-app-0.1.0");
    fs::rename(&first, &renamed).expect("rename the bundle folder");
    assert!(!first.exists(), "the rename did not run");
    let after = named(&renamed);

    assert_eq!(
        after, before,
        "the bundle folder's name entered its lab CID"
    );
    assert_eq!(before.to_string(), WEB_APP_LAB_CID);
}

#[test]
fn moving_the_bundle_to_another_parent_keeps_the_lab_cid() {
    // The folder keeps its name; only its parent and its depth change.
    let root = temp_dir();
    let first = root.path().join("one/web-app");
    assemble_at(&WEB_APP, &first);
    let before = named(&first);

    let moved = root.path().join("two/deeper/still/web-app");
    fs::create_dir_all(moved.parent().expect("a parent")).expect("make the new parent");
    fs::rename(&first, &moved).expect("move the bundle folder");
    assert!(!first.exists(), "the move did not run");
    assert_ne!(
        first.components().count(),
        moved.components().count(),
        "the bundle did not change depth"
    );
    let after = named(&moved);

    assert_eq!(after, before, "the bundle's place entered its lab CID");
    assert_eq!(before.to_string(), WEB_APP_LAB_CID);
}

#[test]
fn changing_the_url_or_store_row_keeps_the_lab_cid() {
    // The bundle folder sits in a listing folder, next to the URL it came
    // from and two Store rows that point at it.
    let listing = temp_dir();
    let bundle = listing.path().join("web-app");
    assemble_at(&WEB_APP, &bundle);
    write_location(
        listing.path(),
        "https://example.invalid/apps/web-app",
        "web-app.tar.gz",
        "web-app",
    );
    let first = named(&bundle);
    let claim = first.to_string();
    check_name(&bundle, &claim).unwrap_or_else(|refusal| panic!("first check: {refusal}"));

    let url = "https://mirror.example.invalid/store/example-web-app-0.1.0";
    write_location(
        listing.path(),
        url,
        "example-web-app-0.1.0.tar.gz",
        "example-web-app",
    );
    let source = fs::read_to_string(listing.path().join("source.url")).expect("read source.url");
    assert_eq!(source, format!("{url}\n"), "the URL did not change");
    let second = named(&bundle);

    assert_eq!(
        second, first,
        "the URL or a Store row beside the bundle entered its lab CID"
    );
    check_name(&bundle, &claim).unwrap_or_else(|refusal| panic!("second check: {refusal}"));
    assert_eq!(claim, WEB_APP_LAB_CID);
}

#[test]
fn file_times_and_modes_do_not_change_the_lab_cid() {
    let bundle = assemble(&WEB_APP);
    let before = named(bundle.path());

    // The root, browser/ and the three files: each gets its own time and a
    // mode it did not have.
    let paths = every_path(bundle.path());
    assert_eq!(paths.len(), 2 + WEB_APP.files.len(), "{paths:?}");
    for (index, path) in paths.iter().enumerate() {
        let time =
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000 + 86_400 * index as u64);
        File::open(path)
            .and_then(|handle| {
                handle.set_times(FileTimes::new().set_accessed(time).set_modified(time))
            })
            .unwrap_or_else(|failure| panic!("set the time of {}: {failure}", path.display()));
        let mode = if path.is_dir() {
            0o750
        } else {
            [0o600, 0o755, 0o400][index % 3]
        };
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("set a mode");
        let changed = fs::symlink_metadata(path).expect("read the changed entry");
        assert_eq!(
            changed.modified().expect("an mtime"),
            time,
            "{}",
            path.display()
        );
        assert_eq!(
            changed.permissions().mode() & 0o7777,
            mode,
            "{}",
            path.display()
        );
    }
    let after = named(bundle.path());

    assert_eq!(after, before, "a file time or mode entered the lab CID");
    assert_eq!(before.to_string(), WEB_APP_LAB_CID);
}
