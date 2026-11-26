//! An empty folder is not part of a bundle's name. The walk reports it.

use std::fs;
use std::path::Path;

use elastos_bundle_identity::{
    checked_bundle, checked_bundle_within_reported, Budget, CheckedBundle, WalkReport,
};

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../lab/capsule-identity/fixtures/web-app")
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for item in fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_tree(&item.path(), &target);
        } else {
            fs::copy(item.path(), &target).unwrap();
        }
    }
}

fn walk(path: &Path) -> (CheckedBundle, WalkReport) {
    let mut report = WalkReport::default();
    let bundle =
        checked_bundle_within_reported(path, Budget::UNLIMITED, &mut report).expect("walk");
    (bundle, report)
}

fn paths(bundle: &CheckedBundle) -> Vec<&str> {
    let mut paths: Vec<&str> = bundle
        .entries()
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    paths.sort();
    paths
}

struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn an_empty_folder_does_not_change_the_cid_and_is_named() {
    let root =
        Scratch(std::env::temp_dir().join(format!("elastos-empty-folders-{}", std::process::id())));
    let _ = fs::remove_dir_all(&root.0);
    fs::create_dir(&root.0).unwrap();
    let plain = root.0.join("plain");
    let with_folders = root.0.join("with-folders");
    copy_tree(&fixture(), &plain);
    copy_tree(&fixture(), &with_folders);
    fs::create_dir(with_folders.join("spare")).unwrap();
    fs::create_dir_all(with_folders.join("nest/inner")).unwrap();

    let (plain_bundle, plain_report) = walk(&plain);
    let (folder_bundle, folder_report) = walk(&with_folders);
    assert_eq!(checked_bundle(&plain).unwrap().cid(), plain_bundle.cid());
    assert_eq!(plain_bundle.cid(), folder_bundle.cid());
    assert_eq!(paths(&plain_bundle), paths(&folder_bundle));
    assert_eq!(plain_report.bytes, folder_report.bytes);
    assert!(plain_report.bytes > 0, "the report counts file bytes");
    assert!(plain_report.empty_folders.is_empty());
    assert_eq!(
        folder_report.empty_folders,
        vec!["nest/inner".to_string(), "spare".to_string()]
    );
    // `nest` holds `inner`, so only the empty one is named. Both folders and
    // `spare` were listed, so the charge is three above the files.
    assert_eq!(folder_report.entries, plain_report.entries + 3);
}

#[test]
fn both_walks_name_an_empty_folder() {
    let unix = include_str!("../src/lib.rs");
    let windows = include_str!("../src/windows_walk.rs");
    assert_eq!(unix.matches("empty_folders.push(").count(), 1);
    assert!(unix.contains("tally.note_empty("));
    assert!(
        windows.contains("tally.note_empty("),
        "Windows walk gap: an empty folder is dropped and not named"
    );
}
