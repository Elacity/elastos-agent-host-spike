//! wc-003a: the lab bundle is named by the hash of its canonical closure, the
//! manifest and the module sorted by path, exact bytes and nothing else. The
//! name is labelled `lab-sha256:` and is never a CID (README.md, ADOPTION.md).
//!
//! The tests call the one naming rule, `wasm_capsule_tools::lab_name`, the
//! same module every lab tool names a bundle through (P10). They live in the
//! root package because the lane gate tests only that package. Every expected
//! value is a literal, or an OS error the test makes itself, never read back
//! from the rule, so a change to the rule is caught rather than mirrored. The
//! tests share one process and run in parallel, so none changes process-wide
//! state (the environment, the working directory or a resource limit).

mod common;

use common::build::TempDir;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use wasm_capsule_tools::lab_name::{
    canonical_closure, lab_name, name_bundle, no_seam, open_regular, read_bundle, read_handle,
    ClosureFile, Moment,
};

/// A lab manifest for the fixture bundle, 175 bytes.
const FIXTURE_MANIFEST: &str = r#"{
  "schema": "wc-003.lab-manifest/v1",
  "name": "fixture",
  "version": "0.0.1",
  "entrypoint": "capsule.wasm",
  "imports": [],
  "resources": { "max_memory_pages": 1 }
}
"#;

/// The smallest core Wasm module: the magic and version 1, no sections.
const FIXTURE_MODULE: &[u8] = b"\0asm\x01\0\0\0";

/// The fixture's lab name. Computed outside this code, with `printf` piped
/// into `shasum -a 256` over the documented bytes (2026-10-25, and again for
/// wc-003a on 2026-10-26), and pinned here.
const FIXTURE_NAME: &str =
    "lab-sha256:0cb69f7b3bd515d31b4b1ad0c50b56a4036e341b359cd5d09cb2ce9b1f3481e1";

/// Why a symlinked closure file is refused.
const SYMLINK_REASON: &str = "is a symlink (a symlink is never followed)";

/// Why a closure file that is a directory, FIFO or device is refused.
const NOT_REGULAR_REASON: &str =
    "is not a regular file (a directory, FIFO or device is never part of the lab closure)";

/// Write a bundle directory holding `manifest` and `module`.
fn write_bundle(dir: &Path, manifest: &[u8], module: &[u8]) -> PathBuf {
    fs::create_dir_all(dir).expect("create the bundle directory");
    fs::write(dir.join("capsule.json"), manifest).expect("write capsule.json");
    fs::write(dir.join("capsule.wasm"), module).expect("write capsule.wasm");
    dir.to_path_buf()
}

fn fixture_bundle(root: &Path) -> PathBuf {
    write_bundle(
        &root.join("bundle"),
        FIXTURE_MANIFEST.as_bytes(),
        FIXTURE_MODULE,
    )
}

/// Name a bundle through the one entry point, or panic with its refusal.
fn name_of(dir: &Path) -> String {
    name_bundle(dir).unwrap_or_else(|refusal| panic!("the bundle was refused: {refusal}"))
}

#[test]
fn bundle_name_is_the_hash_of_the_canonical_closure() {
    let tmp = TempDir::new("bundle-hash");
    let bundle = fixture_bundle(tmp.path());

    // The exact bytes the rule hashes for the fixture, written out by hand
    // from the framing in README.md: the tag, then each file in path order as
    // `<path length> <path> <content length> <content>`.
    assert_eq!(FIXTURE_MANIFEST.len(), 175, "the fixture manifest changed");
    let parts: [&[u8]; 5] = [
        b"wc-003.lab-closure/v1\n",
        b"12 capsule.json 175 ",
        FIXTURE_MANIFEST.as_bytes(),
        b"12 capsule.wasm 8 ",
        FIXTURE_MODULE,
    ];
    let files = read_bundle(&bundle, &mut no_seam).expect("read the fixture bundle");
    assert_eq!(
        canonical_closure(&files),
        parts.concat(),
        "the canonical closure must be exactly the documented bytes"
    );

    // Their sha256 is pinned: the rule and the one entry point both give it.
    assert_eq!(lab_name(&files), FIXTURE_NAME);
    assert_eq!(
        name_of(&bundle),
        FIXTURE_NAME,
        "name_bundle must give the pinned name"
    );
}

#[test]
fn changing_one_wasm_byte_changes_the_name() {
    let tmp = TempDir::new("bundle-wasm-byte");
    let original = fixture_bundle(tmp.path());
    // The same length, so only the module's content differs.
    let mut module = FIXTURE_MODULE.to_vec();
    module[7] ^= 0x01;
    let changed = write_bundle(
        &tmp.path().join("changed"),
        FIXTURE_MANIFEST.as_bytes(),
        &module,
    );
    assert_ne!(
        name_of(&original),
        name_of(&changed),
        "a one-byte change to capsule.wasm must change the lab name"
    );
}

#[test]
fn changing_the_manifest_changes_the_name() {
    let tmp = TempDir::new("bundle-manifest");
    let original = fixture_bundle(tmp.path());
    // Only the declared imports change: an import cannot be declared without a
    // new name.
    let declares_an_import = FIXTURE_MANIFEST.replace(
        r#""imports": []"#,
        r#""imports": [{ "module": "env", "name": "host_entropy" }]"#,
    );
    assert_ne!(declares_an_import, FIXTURE_MANIFEST);
    let changed = write_bundle(
        &tmp.path().join("changed"),
        declares_an_import.as_bytes(),
        FIXTURE_MODULE,
    );
    assert_ne!(
        name_of(&original),
        name_of(&changed),
        "changing the declared imports must change the lab name"
    );
}

#[cfg(unix)]
#[test]
fn file_order_mtime_and_mode_do_not_change_the_name() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::UNIX_EPOCH;

    fn put(path: &Path, bytes: &[u8], mtime_secs: u64, mode: u32) {
        fs::write(path, bytes).expect("write a closure file");
        fs::File::options()
            .write(true)
            .open(path)
            .and_then(|file| file.set_modified(UNIX_EPOCH + Duration::from_secs(mtime_secs)))
            .expect("set the mtime");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set the mode");
    }

    // The same bytes in two bundles, written in opposite orders, with other
    // mtimes, other modes and another directory name.
    let tmp = TempDir::new("bundle-metadata");
    let first = tmp.path().join("first");
    let second = tmp.path().join("second-bundle");
    fs::create_dir(&first).expect("create the first bundle");
    fs::create_dir(&second).expect("create the second bundle");
    put(
        &first.join("capsule.json"),
        FIXTURE_MANIFEST.as_bytes(),
        1_000_000_000,
        0o644,
    );
    put(
        &first.join("capsule.wasm"),
        FIXTURE_MODULE,
        1_000_000_000,
        0o644,
    );
    put(
        &second.join("capsule.wasm"),
        FIXTURE_MODULE,
        1_700_000_000,
        0o755,
    );
    put(
        &second.join("capsule.json"),
        FIXTURE_MANIFEST.as_bytes(),
        1_600_000_000,
        0o600,
    );
    for path in ["capsule.json", "capsule.wasm"] {
        let a = fs::metadata(first.join(path)).expect("stat the first bundle");
        let b = fs::metadata(second.join(path)).expect("stat the second bundle");
        assert_ne!(
            a.modified().ok(),
            b.modified().ok(),
            "{path}: the mtimes must differ"
        );
        assert_ne!(
            a.permissions().mode(),
            b.permissions().mode(),
            "{path}: the modes must differ"
        );
    }
    assert_eq!(
        name_of(&first),
        name_of(&second),
        "write order, mtime and mode must not change the lab name"
    );

    // Nor the order the files arrive in: the rule sorts them by path.
    let listed = read_bundle(&first, &mut no_seam).expect("read the first bundle");
    let reversed: Vec<ClosureFile> = listed.iter().rev().cloned().collect();
    assert_ne!(listed, reversed);
    assert_eq!(
        lab_name(&listed),
        lab_name(&reversed),
        "the order the files arrive in must not change the lab name"
    );
}

#[test]
fn an_extra_file_in_the_bundle_is_refused() {
    let tmp = TempDir::new("bundle-extra");
    let bundle = fixture_bundle(tmp.path());
    let extra = bundle.join("notes.txt");
    fs::write(&extra, b"not part of the closure").expect("write the extra file");

    let refusal = name_bundle(&bundle).expect_err("a bundle with an extra file must be refused");
    assert_eq!(refusal.path, extra, "the refusal must name the extra file");
    assert_eq!(
        refusal.reason,
        "is not part of the lab closure (a lab bundle holds exactly capsule.json and capsule.wasm)",
        "the refusal must say why"
    );
}

#[test]
fn a_missing_closure_file_is_refused() {
    for missing in ["capsule.json", "capsule.wasm"] {
        let tmp = TempDir::new("bundle-missing");
        let bundle = fixture_bundle(tmp.path());
        fs::remove_file(bundle.join(missing)).expect("remove a closure file");

        let refusal =
            name_bundle(&bundle).expect_err("a bundle without a closure file must be refused");
        assert_eq!(
            refusal.path,
            bundle.join(missing),
            "the refusal must name the missing file"
        );
        assert_eq!(
            refusal.reason, "is missing from the lab closure",
            "the refusal must say why"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_in_the_bundle_is_refused() {
    let tmp = TempDir::new("bundle-symlink");
    let bundle = fixture_bundle(tmp.path());
    // The link points at the right bytes, outside the bundle. It is refused,
    // not followed: the name only ever covers bytes inside the bundle.
    let outside = tmp.path().join("outside.wasm");
    fs::write(&outside, FIXTURE_MODULE).expect("write the outside module");
    fs::remove_file(bundle.join("capsule.wasm")).expect("remove the module");
    std::os::unix::fs::symlink(&outside, bundle.join("capsule.wasm")).expect("link the module");

    let refusal = name_bundle(&bundle).expect_err("a symlinked closure file must be refused");
    assert_eq!(
        refusal.path,
        bundle.join("capsule.wasm"),
        "the refusal must name the link"
    );
    assert_eq!(refusal.reason, SYMLINK_REASON, "the refusal must say why");
}

/// Put a symlink to `target` where the file at `path` was.
#[cfg(unix)]
fn replace_with_symlink(path: &Path, target: &Path) {
    fs::remove_file(path).expect("remove the closure file");
    std::os::unix::fs::symlink(target, path).expect("link the closure file");
}

#[cfg(unix)]
#[test]
fn a_closure_file_replaced_by_a_symlink_before_it_is_opened_is_refused() {
    let tmp = TempDir::new("bundle-swap-before-open");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");
    // The same bytes, outside the bundle, so following the link would give the
    // same name: the refusal is about the link, not the bytes.
    let outside = tmp.path().join("outside.wasm");
    fs::write(&outside, FIXTURE_MODULE).expect("write the outside module");

    // The listing names capsule.wasm as a regular file. Between that
    // inspection and the open, it becomes a link.
    let mut swapped = false;
    let refusal = read_bundle(&bundle, &mut |moment, path| {
        if moment == Moment::BeforeOpen && path == module {
            replace_with_symlink(path, &outside);
            swapped = true;
        }
    })
    .expect_err("a closure file that became a link before it was opened must be refused");
    assert!(
        swapped,
        "the swap must happen before capsule.wasm is opened"
    );
    assert_eq!(refusal.path, module, "the refusal must name the link");
    assert_eq!(
        refusal.reason, SYMLINK_REASON,
        "the open itself must refuse the link"
    );
}

#[cfg(unix)]
#[test]
fn a_closure_file_replaced_after_it_is_checked_is_read_from_its_handle() {
    let tmp = TempDir::new("bundle-swap-before-read");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");
    // Other bytes, outside the bundle: a reader that went back to the path
    // after its check would name these.
    let mut other = FIXTURE_MODULE.to_vec();
    other[7] ^= 0x01;
    let outside = tmp.path().join("outside.wasm");
    fs::write(&outside, &other).expect("write the outside module");

    // capsule.wasm is open and its handle checked; then, before it is read,
    // the path becomes a link to the other bytes.
    let mut swapped = false;
    let files = read_bundle(&bundle, &mut |moment, path| {
        if moment == Moment::BeforeRead && path == module {
            replace_with_symlink(path, &outside);
            swapped = true;
        }
    })
    .unwrap_or_else(|refusal| panic!("the opened, checked file must still be read: {refusal}"));
    assert!(swapped, "the swap must happen before capsule.wasm is read");
    assert_eq!(
        lab_name(&files),
        FIXTURE_NAME,
        "the name must cover the file that was opened and checked, never what its path points at later"
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_in_the_bundle_is_refused_without_blocking() {
    let tmp = TempDir::new("bundle-fifo");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");
    fs::remove_file(&module).expect("remove the module");
    let made = Command::new("mkfifo")
        .arg(&module)
        .status()
        .expect("spawn mkfifo");
    assert!(made.success(), "mkfifo must make the FIFO");

    // Nothing ever opens the FIFO's other end, so an open that waits for it
    // waits forever: the reader runs on its own thread, against a deadline.
    let (sender, receiver) = mpsc::channel();
    let dir = bundle.clone();
    thread::spawn(move || {
        let _ = sender.send(name_bundle(&dir));
    });
    let named = receiver
        .recv_timeout(Duration::from_secs(10))
        .expect("the reader must refuse a FIFO at once, not wait on it");
    let refusal = named.expect_err("a FIFO in the bundle must be refused");
    assert_eq!(refusal.path, module, "the refusal must name the FIFO");
    assert_eq!(
        refusal.reason, NOT_REGULAR_REASON,
        "the refusal must say why"
    );
}

#[test]
fn directory_in_bundle_is_refused() {
    let tmp = TempDir::new("bundle-directory");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");
    fs::remove_file(&module).expect("remove the module");
    fs::create_dir(&module).expect("put a directory at capsule.wasm");

    let refusal = name_bundle(&bundle).expect_err("a directory in the closure must be refused");
    assert_eq!(refusal.path, module, "the refusal must name the directory");
    assert_eq!(
        refusal.reason, NOT_REGULAR_REASON,
        "the refusal must say why"
    );
}

/// Only root can make a device node, so this hands the one open the system's
/// own `/dev/null`, a character device. Every closure file `read_bundle` reads
/// goes through this same open.
#[cfg(unix)]
#[test]
fn device_is_refused() {
    use std::os::unix::fs::FileTypeExt;

    let device = Path::new("/dev/null");
    assert!(
        fs::metadata(device)
            .expect("stat /dev/null")
            .file_type()
            .is_char_device(),
        "/dev/null must be a character device"
    );
    let refusal = open_regular(device, fs::OpenOptions::new().read(true))
        .expect_err("a device must be refused");
    assert_eq!(refusal.path, device, "the refusal must name the device");
    assert_eq!(
        refusal.reason, NOT_REGULAR_REASON,
        "the refusal must say why"
    );
}

#[test]
fn unlistable_bundle_reports_path_and_cause() {
    let tmp = TempDir::new("bundle-unlistable");
    // No directory at all, and a regular file where the directory should be.
    let missing = tmp.path().join("no-such-bundle");
    let not_a_directory = tmp.path().join("a-file");
    fs::write(&not_a_directory, FIXTURE_MANIFEST).expect("write the file");

    for dir in [missing, not_a_directory] {
        // The cause the OS gives for listing this path, from the same call.
        let cause = fs::read_dir(&dir).expect_err("the listing must fail");
        let refusal = name_bundle(&dir).expect_err("a path that cannot be listed must be refused");
        assert_eq!(refusal.path, dir, "the refusal must name the directory");
        assert_eq!(
            refusal.reason,
            format!("cannot be listed as a lab bundle ({cause})"),
            "the refusal must carry the listing's cause"
        );
    }
}

#[test]
fn open_failure_reports_path_and_cause() {
    let tmp = TempDir::new("bundle-open-failure");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");

    // The listing names capsule.wasm. Before it is opened it is removed, so
    // the open itself fails.
    let mut removed = false;
    let refusal = read_bundle(&bundle, &mut |moment, path| {
        if moment == Moment::BeforeOpen && path == module {
            fs::remove_file(path).expect("remove capsule.wasm");
            removed = true;
        }
    })
    .expect_err("a closure file that cannot be opened must be refused");
    assert!(removed, "capsule.wasm must be removed before it is opened");

    // The cause the OS gives for opening the removed file.
    let cause = fs::File::open(&module).expect_err("the open must fail");
    assert_eq!(refusal.path, module, "the refusal must name the file");
    assert_eq!(
        refusal.reason,
        format!("cannot be opened ({cause})"),
        "the refusal must carry the open's cause"
    );
}

#[test]
fn read_failure_reports_path_and_cause() {
    let tmp = TempDir::new("bundle-read-failure");
    let bundle = fixture_bundle(tmp.path());
    let module = bundle.join("capsule.wasm");

    // A regular file opened for reading cannot be made to fail on demand, so
    // the reader gets a handle opened write-only: its read fails in the OS,
    // as a real read of a real file can.
    let write_only = fs::File::options()
        .write(true)
        .open(&module)
        .expect("open capsule.wasm write-only");
    let cause = (&write_only)
        .read_to_end(&mut Vec::new())
        .expect_err("reading a write-only handle must fail");

    let refusal = read_handle(&module, &write_only)
        .expect_err("a closure file that cannot be read must be refused");
    assert_eq!(refusal.path, module, "the refusal must name the file");
    assert_eq!(
        refusal.reason,
        format!("cannot be read ({cause})"),
        "the refusal must carry the read's cause"
    );
}

#[test]
fn lab_name_carries_the_lab_prefix_never_cid() {
    let tmp = TempDir::new("bundle-prefix");
    let name = name_of(&fixture_bundle(tmp.path()));

    let digest = name
        .strip_prefix("lab-sha256:")
        .unwrap_or_else(|| panic!("a lab name must be labelled `lab-sha256:`, got {name:?}"));
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "a lab name is 64 lowercase hex digits after its label, got {name:?}"
    );
    let lower = name.to_ascii_lowercase();
    assert!(
        !lower.contains("cid") && !lower.contains("bafy"),
        "a lab name must never be called or look like a CID, got {name:?}"
    );
}
