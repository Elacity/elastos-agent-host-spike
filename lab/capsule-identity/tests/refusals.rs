//! Each refusal returns no name and says why.
mod common;

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;

use capsule_identity::{entry_kind, entry_path, lab_cid, EntryKind, Refusal};
use common::*;
use elastos_common::CapsuleManifest;
use rustix::fs::FileType;

/// content-sample's manifest text, for edited copies.
fn content_sample_manifest() -> String {
    String::from_utf8(read_fixture(&CONTENT_SAMPLE, "capsule.json")).expect("UTF-8 manifest")
}

/// A content-sample bundle whose `capsule.json` is `manifest`.
fn bundle_with_manifest(manifest: &str) -> tempfile::TempDir {
    let bundle = assemble(&CONTENT_SAMPLE);
    write_file(bundle.path(), "capsule.json", manifest.as_bytes());
    bundle
}

#[test]
fn bundle_without_capsule_json_is_refused() {
    let bundle = temp_dir();
    let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
    write_file(bundle.path(), "sample.example", &sample);
    // A valid manifest below the root is not the bundle's manifest.
    let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
    write_file(bundle.path(), "nested/capsule.json", &manifest);

    let refusal = lab_cid(bundle.path()).expect_err("a bundle without capsule.json gets no name");
    assert_eq!(refusal, Refusal::NoManifest);
    assert_eq!(
        refusal.to_string(),
        "no capsule.json file at the bundle root"
    );
}

#[test]
fn manifest_with_an_unknown_field_is_refused() {
    let manifest = content_sample_manifest().replacen('{', "{\n  \"lab_cid\": \"x\",", 1);
    let refusal = lab_cid(bundle_with_manifest(&manifest).path())
        .expect_err("a manifest with a field the Runtime does not know gets no name");

    // The reason is the Runtime type's own error text, and it names the field.
    let runtime_text = serde_json::from_slice::<CapsuleManifest>(manifest.as_bytes())
        .expect_err("the Runtime type refuses an unknown field")
        .to_string();
    assert!(
        runtime_text.contains("unknown field `lab_cid`"),
        "{runtime_text}"
    );
    assert_eq!(refusal, Refusal::ManifestUnparsed(runtime_text.clone()));
    assert_eq!(
        refusal.to_string(),
        format!("the Runtime's CapsuleManifest refused to parse capsule.json: {runtime_text}")
    );
}

#[test]
fn manifest_that_fails_runtime_validate_is_refused() {
    let original = content_sample_manifest();
    let manifest = original.replacen(
        "\"schema\": \"elastos.capsule/v1\"",
        "\"schema\": \"elastos.capsule/v2\"",
        1,
    );
    assert_ne!(manifest, original, "the fixture names its schema");
    let refusal = lab_cid(bundle_with_manifest(&manifest).path())
        .expect_err("a manifest that validate() refuses gets no name");

    // The Runtime type parses it; the reason is validate()'s own text.
    let runtime_text = serde_json::from_slice::<CapsuleManifest>(manifest.as_bytes())
        .expect("the Runtime type parses any schema string")
        .validate()
        .expect_err("validate() refuses the v2 schema");
    assert!(
        runtime_text.contains("elastos.capsule/v2"),
        "{runtime_text}"
    );
    assert_eq!(refusal, Refusal::ManifestInvalid(runtime_text.clone()));
    assert_eq!(
        refusal.to_string(),
        format!("the Runtime's CapsuleManifest::validate() refused capsule.json: {runtime_text}")
    );
}

/// `capsule.json` gets the same type check as every entry, before it is
/// opened. One test per kind, so a falsifier must fail each on its own.
mod special_file_manifest_is_refused_before_read {
    use super::*;

    /// A content-sample bundle that has no `capsule.json` yet.
    fn bundle_without_manifest() -> tempfile::TempDir {
        let bundle = temp_dir();
        let sample = read_fixture(&CONTENT_SAMPLE, "sample.example");
        write_file(bundle.path(), "sample.example", &sample);
        bundle
    }

    #[test]
    fn symlink() {
        // capsule.json links to a valid manifest outside the bundle. Only
        // the type check can refuse it: a read through the link would name it.
        let outside = temp_dir();
        let manifest = read_fixture(&CONTENT_SAMPLE, "capsule.json");
        write_file(outside.path(), "capsule.json", &manifest);
        let bundle = bundle_without_manifest();
        std::os::unix::fs::symlink(
            outside.path().join("capsule.json"),
            bundle.path().join("capsule.json"),
        )
        .expect("link capsule.json");
        let refusal = lab_cid_bounded(bundle.path(), unobserved)
            .expect_err("a linked capsule.json gets no name");
        assert_eq!(
            refusal,
            Refusal::NotRegularFile {
                path: "capsule.json".into(),
                kind: "symbolic link"
            }
        );
        assert_eq!(
            refusal.to_string(),
            "capsule.json is a symbolic link: the lab CID covers only regular files and never follows a link"
        );
    }

    #[test]
    fn fifo() {
        // Opening a FIFO to read blocks, so the bound catches a read that
        // comes before the type check.
        let bundle = bundle_without_manifest();
        make_fifo(&bundle.path().join("capsule.json"));
        let refusal = lab_cid_bounded(bundle.path(), unobserved)
            .expect_err("a FIFO capsule.json gets no name");
        assert_eq!(
            refusal,
            Refusal::NotRegularFile {
                path: "capsule.json".into(),
                kind: "FIFO"
            }
        );
        assert_eq!(
            refusal.to_string(),
            "capsule.json is a FIFO: the lab CID covers only regular files and never follows a link"
        );
    }
}

#[test]
fn symlink_in_bundle_is_refused_with_its_path() {
    let bundle = assemble(&WEB_APP);
    symlink("app.js", bundle.path().join("browser/alias.js")).expect("link a payload");
    let refusal = lab_cid(bundle.path()).expect_err("a symlink is refused, never followed");
    assert_eq!(
        refusal,
        Refusal::NotRegularFile {
            path: "browser/alias.js".into(),
            kind: "symbolic link"
        }
    );
    assert_eq!(
        refusal.to_string(),
        "browser/alias.js is a symbolic link: the lab CID covers only regular files and never follows a link"
    );
}

/// A FIFO, socket or device payload is refused, never read or skipped. One
/// test per kind, so a falsifier must fail each on its own.
mod special_payload_is_refused_with_its_path {
    use super::*;

    #[test]
    fn fifo() {
        // A FIFO in a folder. Opening it to read would block, so the call
        // is bounded.
        let bundle = assemble(&WEB_APP);
        make_fifo(&bundle.path().join("browser/pipe"));
        let refusal =
            lab_cid_bounded(bundle.path(), unobserved).expect_err("a FIFO payload gets no name");
        assert_eq!(
            refusal,
            Refusal::NotRegularFile {
                path: "browser/pipe".into(),
                kind: "FIFO"
            }
        );
        assert_eq!(
            refusal.to_string(),
            "browser/pipe is a FIFO: the lab CID covers only regular files and never follows a link"
        );
    }

    #[test]
    fn socket() {
        // A socket at the bundle root.
        let bundle = assemble(&WEB_APP);
        let _socket = UnixListener::bind(bundle.path().join("bus.sock")).expect("bind a socket");
        let refusal =
            lab_cid_bounded(bundle.path(), unobserved).expect_err("a socket payload gets no name");
        assert_eq!(
            refusal,
            Refusal::NotRegularFile {
                path: "bus.sock".into(),
                kind: "socket"
            }
        );
        assert_eq!(
            refusal.to_string(),
            "bus.sock is a socket: the lab CID covers only regular files and never follows a link"
        );
    }

    #[test]
    fn device() {
        // A test cannot make a device node, so a real device's own type
        // goes through the same check the walk gives every entry.
        let device = FileType::from_raw_mode(
            rustix::fs::lstat("/dev/null")
                .expect("read /dev/null's own type")
                .st_mode,
        );
        assert_eq!(entry_kind(device), EntryKind::Special("character device"));
    }
}

#[test]
fn non_utf8_path_is_refused() {
    // APFS cannot hold this name, so the walk's own name check gets it in
    // memory: Latin-1 `é` (0xE9) is not UTF-8.
    let name = OsStr::from_bytes(b"caf\xe9.txt");
    let refusal = entry_path("browser", name).expect_err("a name that is not UTF-8 is refused");
    assert_eq!(
        refusal,
        Refusal::NonUtf8Name {
            path: "browser/caf\u{fffd}.txt".into()
        }
    );
    assert_eq!(
        refusal.to_string(),
        "browser/caf\u{fffd}.txt has a name that is not UTF-8: the lab CID names only UTF-8 paths"
    );
    // The same check keeps a UTF-8 name as it is, at the root and in a folder.
    assert_eq!(
        entry_path("", OsStr::new("capsule.json")),
        Ok("capsule.json".to_owned())
    );
    assert_eq!(
        entry_path("browser", OsStr::new("app.js")),
        Ok("browser/app.js".to_owned())
    );
}

#[test]
fn unreadable_folder_is_refused_with_its_path() {
    // A normal user cannot list a folder with mode 000 (root can; the gates
    // run as the Mac's user). Skipping it would name the bundle without the
    // folder's files.
    let bundle = assemble(&WEB_APP);
    let browser = bundle.path().join("browser");
    fs::set_permissions(&browser, fs::Permissions::from_mode(0o000)).expect("lock browser/");
    let result = lab_cid(bundle.path());
    // Unlock before any assertion, so the temp dir can always be removed.
    fs::set_permissions(&browser, fs::Permissions::from_mode(0o755)).expect("unlock browser/");

    let refusal = result.expect_err("an unreadable folder is refused, never skipped");
    assert!(
        matches!(&refusal, Refusal::Unreadable { path, .. } if path == "browser"),
        "{refusal:?}"
    );
    assert!(
        refusal.to_string().starts_with("could not read browser: "),
        "{refusal}"
    );
}
