#![cfg(windows)]

use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{symlink_dir, symlink_file, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use elastos_bundle_identity::{
    checked_bundle, checked_bundle_observed, checked_bundle_within, entry_kind, Budget, EntryKind,
    Moment, Refusal,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

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
fn link_above_root_and_canonical_root() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let real = temp.0.join("real");
    fs::create_dir(&real).unwrap();
    let moved = real.join("bundle");
    fs::rename(&root, &moved).unwrap();
    let alias = temp.0.join("alias");
    symlink_dir(&real, &alias).unwrap();
    let result = checked_bundle(&alias.join("bundle"));
    assert!(
        matches!(&result, Err(Refusal::NotRegularFile { path, kind: "reparse point" })
        if path.ends_with("alias")),
        "{result:?}"
    );
    fs::remove_dir(&alias).unwrap();
    assert!(checked_bundle(&moved.canonicalize().unwrap()).is_ok());
}

#[test]
fn invalid_root_paths_are_typed() {
    for path in [r"\\server\share\bundle", r"C:bundle"] {
        assert!(
            matches!(
                checked_bundle(Path::new(path)),
                Err(Refusal::InvalidRootPath { .. })
            ),
            "{path}"
        );
    }
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
    assert_eq!(
        entry_kind(&fs::symlink_metadata(&junction).unwrap()),
        EntryKind::Special("reparse point")
    );
    fs::remove_dir(&junction).unwrap();
}

fn mount_point_buffer(target: &Path) -> Vec<u8> {
    let canonical = target.canonicalize().unwrap();
    let raw = canonical.to_string_lossy();
    let local = raw.strip_prefix(r"\\?\").expect("verbatim disk path");
    let substitute: Vec<u16> = format!(r"\??\{local}").encode_utf16().collect();
    let print: Vec<u16> = target.as_os_str().encode_wide().collect();
    let sub_bytes = (substitute.len() * 2) as u16;
    let print_bytes = (print.len() * 2) as u16;
    let print_offset = sub_bytes + 2;
    let data_len = 8 + print_offset + print_bytes + 2;
    let mut buf = Vec::new();
    buf.extend(0xA000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    buf.extend(data_len.to_le_bytes());
    buf.extend(0u16.to_le_bytes());
    for word in [0u16, sub_bytes, print_offset, print_bytes] {
        buf.extend(word.to_le_bytes());
    }
    for word in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        buf.extend(word.to_le_bytes());
    }
    buf
}

fn set_junction_with_attributes_only(folder: &Path, target: &Path) -> std::io::Result<()> {
    let held = fs::OpenOptions::new()
        .access_mode(FILE_WRITE_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(folder)?;
    let buffer = mount_point_buffer(target);
    let mut returned = 0u32;
    // SAFETY: the open handle and reparse buffer remain live for this synchronous ioctl.
    let ok = unsafe {
        DeviceIoControl(
            held.as_raw_handle(),
            0x0009_00A4,
            buffer.as_ptr().cast(),
            buffer.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[test]
fn attribute_only_junction_conversion_cannot_redirect_walk() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let folder = root.join("empty");
    fs::create_dir(&folder).unwrap();
    let target = temp.0.join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("secret"), b"outside bytes").unwrap();
    let mut conversion = None;
    let result = checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::AfterCheck && path == "empty" {
            conversion = Some(set_junction_with_attributes_only(&folder, &target));
        }
    });
    let conversion = conversion.expect("conversion was attempted while the walk held empty");
    eprintln!("attribute-only FSCTL_SET_REPARSE_POINT: {conversion:?}");
    if conversion.is_ok() {
        assert!(
            matches!(&result, Err(Refusal::NotRegularFile {
            path, kind: "reparse point" }) if path == "empty"),
            "{result:?}"
        );
        fs::remove_dir(&folder).unwrap();
    } else {
        assert!(result.is_ok(), "{result:?}; conversion: {conversion:?}");
    }
}

#[test]
fn folder_swapped_for_junction_after_listing_is_refused() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let folder = root.join("swapped-folder");
    fs::create_dir(&folder).unwrap();
    let target = temp.0.join("target");
    fs::create_dir(&target).unwrap();
    let mut changed = false;
    let result = checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::BeforeOpen && path == "swapped-folder" {
            fs::remove_dir(&folder).unwrap();
            let output = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&folder)
                .arg(&target)
                .output()
                .unwrap();
            assert!(output.status.success(), "mklink: {output:?}");
            changed = true;
        }
    });
    assert!(changed);
    assert!(matches!(result, Err(Refusal::NotRegularFile {
        path, kind: "reparse point" }) if path == "swapped-folder"));
    fs::remove_dir(&folder).unwrap();
}

#[test]
fn a_held_folder_cannot_be_renamed() {
    let temp = TestTree::new();
    let root = temp.bundle();
    let folder = root.join("held-folder");
    fs::create_dir(&folder).unwrap();
    let mut rename_blocked = false;
    checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::AfterCheck && path == "held-folder" {
            rename_blocked = fs::rename(&folder, root.join("moved-folder")).is_err();
        }
    })
    .unwrap();
    assert!(rename_blocked);
}

#[test]
fn a_held_root_ancestor_allows_an_incoming_rename() {
    let temp = TestTree::new();
    let source_tree = TestTree::new();
    let root = temp.bundle();
    let source = source_tree.0.join("source");
    fs::write(&source, b"moved").unwrap();
    let destination = temp.0.join("incoming");
    let mut moved = false;
    checked_bundle_observed(&root, |moment, path| {
        if moment == Moment::AfterCheck && path == "capsule.json" {
            fs::rename(&source, &destination).unwrap();
            moved = true;
        }
    })
    .unwrap();
    assert!(moved);
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
