#![cfg(windows)]

use std::fs;
use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use elastos_bundle_identity::{
    checked_bundle, checked_bundle_observed, checked_bundle_within, Budget, Moment, Refusal,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct TestTree(PathBuf);

impl TestTree {
    fn new() -> Self {
        let parent = std::env::temp_dir();
        loop {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("bundle-identity-{}-{id}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create test tree: {error}"),
            }
        }
    }

    fn bundle(&self) -> PathBuf {
        let root = self.0.join("bundle");
        fs::create_dir(&root).unwrap();
        // Use the same valid web-app bundle as the Unix walk tests. Its
        // manifest is independent of the Component WIT hash.
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../lab/capsule-identity/fixtures/web-app");
        fs::create_dir(root.join("browser")).unwrap();
        for name in ["capsule.json", "browser/app.js", "browser/index.html"] {
            fs::copy(fixture.join(name), root.join(name)).unwrap();
        }
        root
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn regular_files_and_nested_directories_are_read() {
    let temp = TestTree::new();
    let root = temp.bundle();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/payload"), b"checked bytes").unwrap();
    let checked = checked_bundle(&root).unwrap();
    assert!(checked
        .entries()
        .iter()
        .any(|entry| entry.path == "nested/payload" && entry.content == b"checked bytes"));
}

#[test]
fn symlink_file_and_root_ancestor_are_refused() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let link = root.join("linked-file");
    symlink_file(root.join("capsule.json"), &link).unwrap();
    assert!(matches!(
        checked_bundle(&root),
        Err(Refusal::NotRegularFile {
            kind: "reparse point",
            ..
        })
    ));
    fs::remove_file(&link).unwrap();

    let alias = temp.0.join("alias");
    symlink_dir(&root, &alias).unwrap();
    assert!(matches!(
        checked_bundle(&alias),
        Err(Refusal::NotRegularFile {
            kind: "reparse point",
            ..
        })
    ));
    fs::remove_dir(&alias).unwrap();
}

#[test]
fn junction_is_refused() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let target = temp.0.join("target");
    fs::create_dir(&target).unwrap();
    let junction = root.join("junction");
    let output = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(&junction)
        .arg(&target)
        .output()
        .unwrap();
    assert!(output.status.success(), "mklink: {:?}", output);
    assert!(matches!(
        checked_bundle(&root),
        Err(Refusal::NotRegularFile {
            kind: "reparse point",
            ..
        })
    ));
    fs::remove_dir(&junction).unwrap();
}

#[test]
fn open_handle_size_bound_is_enforced() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let budget = Budget {
        max_total_bytes: 0,
        ..Budget::UNLIMITED
    };
    assert!(matches!(
        checked_bundle_within(&root, budget),
        Err(Refusal::OverBudget {
            limit: "total bytes",
            ..
        })
    ));
}

#[test]
fn a_link_swapped_after_listing_is_refused() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let swapped = root.join("swapped");
    fs::write(&swapped, b"old").unwrap();
    let mut changed = false;
    let result = checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::BeforeOpen && path == "swapped" {
            fs::remove_file(&swapped).unwrap();
            symlink_file(root.join("capsule.json"), &swapped).unwrap();
            changed = true;
        }
    });
    assert!(changed);
    assert!(matches!(
        result,
        Err(Refusal::NotRegularFile {
            kind: "reparse point",
            ..
        })
    ));
    fs::remove_file(&swapped).unwrap();
}

#[test]
fn a_checked_file_cannot_be_replaced_during_its_read() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let pinned = root.join("pinned");
    fs::write(&pinned, b"bytes").unwrap();
    let mut replacement_blocked = false;
    checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::AfterCheck && path == "pinned" {
            replacement_blocked = fs::rename(&pinned, root.join("moved")).is_err();
        }
    })
    .unwrap();
    assert!(replacement_blocked);
}
