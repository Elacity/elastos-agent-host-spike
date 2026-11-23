use std::io::Write;
use std::path::Path;
use std::process::Command;

use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

use super::open::{
    clear_created_verify_failure, create_owner_dir, fail_next_created_verify, open_owner_file, Disp,
};
use super::sd::{verify_owner_only, OWNER_USE};
use crate::CustodyError;

const MARKER: &[u8] = b"w1-owner-bytes-stay";

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "elastos-w1-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ClearVerifyFailure;

impl Drop for ClearVerifyFailure {
    fn drop(&mut self) {
        clear_created_verify_failure();
    }
}

fn icacls(args: &[&str]) {
    let output = Command::new("icacls").args(args).output().expect("icacls");
    assert!(
        output.status.success(),
        "icacls {args:?}\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn grant_users_full(dir: &Path) {
    let path = dir.display().to_string();
    icacls(&[&path, "/inheritance:r"]);
    icacls(&[&path, "/grant", "*S-1-5-32-545:(OI)(CI)(F)"]);
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.display().to_string(),
            &target.display().to_string(),
        ])
        .status()
        .expect("mklink");
    assert!(status.success(), "mklink /J");
}

fn write_marker(dir: &Path) -> std::path::PathBuf {
    let file = dir.join("kept.bin");
    std::fs::write(&file, MARKER).unwrap();
    file
}

#[test]
fn junction_at_target_name_is_refused_and_bytes_stay() {
    let scratch = Scratch::new("junction-target");
    let target = scratch.0.join("target");
    std::fs::create_dir(&target).unwrap();
    let marker = write_marker(&target);
    let link = scratch.0.join("link");
    junction(&link, &target);
    for disp in [Disp::CreateNew, Disp::OpenExisting, Disp::OpenOrCreate] {
        let error = open_owner_file(&link, OWNER_USE, disp).expect_err("junction");
        assert!(
            matches!(error, CustodyError::ReparsePoint { .. }),
            "{error}"
        );
    }
    assert_eq!(std::fs::read(marker).unwrap(), MARKER);
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
}

#[test]
fn permissive_parent_keeps_owner_only_dacl_without_inherited_aces() {
    let scratch = Scratch::new("permissive");
    grant_users_full(&scratch.0);
    let plain = scratch.0.join("plain");
    std::fs::write(&plain, b"plain").unwrap();
    let plain_file = std::fs::File::open(&plain).unwrap();
    assert!(
        matches!(
            verify_owner_only(&plain_file, &plain),
            Err(CustodyError::ForeignDacl { .. } | CustodyError::NotOwner { .. })
        ),
        "a file created under Users full control must not pass"
    );
    let owned = scratch.0.join("owned");
    let file = open_owner_file(&owned, OWNER_USE, Disp::CreateNew).unwrap();
    verify_owner_only(&file, &owned).unwrap();
    drop(file);
    let again = open_owner_file(&owned, FILE_GENERIC_READ, Disp::OpenExisting).unwrap();
    verify_owner_only(&again, &owned).unwrap();
    let dir_path = scratch.0.join("dir");
    let dir = create_owner_dir(&dir_path).unwrap();
    verify_owner_only(&dir, &dir_path).unwrap();
}

#[test]
fn reparse_point_parent_is_refused_and_bytes_stay() {
    let scratch = Scratch::new("junction-parent");
    let target = scratch.0.join("target");
    std::fs::create_dir(&target).unwrap();
    let marker = write_marker(&target);
    let link = scratch.0.join("link");
    junction(&link, &target);
    let error =
        open_owner_file(&link.join("child"), OWNER_USE, Disp::CreateNew).expect_err("parent");
    assert!(
        matches!(error, CustodyError::ReparsePoint { .. }),
        "{error}"
    );
    let dir_error = create_owner_dir(&link.join("child-dir")).expect_err("parent dir");
    assert!(
        matches!(dir_error, CustodyError::ReparsePoint { .. }),
        "{dir_error}"
    );
    assert_eq!(std::fs::read(marker).unwrap(), MARKER);
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1);
}

#[test]
fn read_back_verifies_owner_only_dacl() {
    let scratch = Scratch::new("read-back");
    let path = scratch.0.join("note");
    let mut file = open_owner_file(&path, OWNER_USE, Disp::CreateNew).unwrap();
    file.write_all(b"stay").unwrap();
    verify_owner_only(&file, &path).unwrap();
    drop(file);
    assert!(open_owner_file(&path, OWNER_USE, Disp::CreateNew).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"stay");
    let again = open_owner_file(&path, FILE_GENERIC_READ, Disp::OpenExisting).unwrap();
    verify_owner_only(&again, &path).unwrap();
    drop(again);
    let third = open_owner_file(&path, OWNER_USE, Disp::OpenOrCreate).unwrap();
    verify_owner_only(&third, &path).unwrap();
    let fresh = scratch.0.join("fresh");
    let created = open_owner_file(&fresh, OWNER_USE, Disp::OpenOrCreate).unwrap();
    verify_owner_only(&created, &fresh).unwrap();
}

#[test]
fn everyone_ace_fails_verify_owner_only() {
    let scratch = Scratch::new("everyone");
    let path = scratch.0.join("note");
    let file = open_owner_file(&path, OWNER_USE, Disp::CreateNew).unwrap();
    verify_owner_only(&file, &path).unwrap();
    drop(file);
    icacls(&[&path.display().to_string(), "/grant", "*S-1-1-0:(F)"]);
    let opened = std::fs::File::open(&path).unwrap();
    let error = verify_owner_only(&opened, &path).expect_err("everyone");
    assert!(matches!(error, CustodyError::ForeignDacl { .. }), "{error}");
}

#[test]
fn create_whose_verify_fails_is_removed() {
    let scratch = Scratch::new("verify-removed");
    let marker = write_marker(&scratch.0);
    let path = scratch.0.join("new-object");
    let _clear = ClearVerifyFailure;
    fail_next_created_verify();
    let error = open_owner_file(&path, OWNER_USE, Disp::CreateNew).expect_err("verify");
    assert!(matches!(error, CustodyError::ForeignDacl { .. }), "{error}");
    assert!(
        !path.exists(),
        "a create whose verify fails must remove the new object"
    );
    assert_eq!(std::fs::read(&marker).unwrap(), MARKER);
    assert!(std::fs::read_dir(&scratch.0)
        .unwrap()
        .all(|entry| entry.unwrap().file_name() != "new-object"));
}
