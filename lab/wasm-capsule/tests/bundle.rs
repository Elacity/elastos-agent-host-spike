//! wc-003: the lab bundle is named by the hash of its canonical closure, the
//! manifest and the module sorted by path, exact bytes and nothing else. The
//! name is labelled `lab-sha256:` and is never a CID (README.md, ADOPTION.md).
//!
//! The tests run the real command, `tools/bundle`, and the one closure rule it
//! names bundles with, compiled here from the same file. Every expected value
//! is a literal (or the Cargo package's own name and version), never read back
//! from that rule, so a change to the rule is caught rather than mirrored.

mod common;

// The one naming rule, from the same source file the `bundle` tool compiles.
#[path = "../tools/lab_name.rs"]
mod lab_name;

use common::build::{lane_dir, sha256_file, Receipt, TempDir};
use common::json::{self, Value};
use lab_name::{
    canonical_closure, lab_name, name_bundle, no_seam, read_bundle, ClosureFile, Moment,
};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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

/// The fixture's lab name. Computed once outside this code, with `printf` and
/// `shasum -a 256` over the documented bytes (2026-10-25), and pinned here.
const FIXTURE_NAME: &str =
    "lab-sha256:0cb69f7b3bd515d31b4b1ad0c50b56a4036e341b359cd5d09cb2ce9b1f3481e1";

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

/// Name a bundle through the closure rule, or panic with its refusal.
fn name_of(dir: &Path) -> String {
    name_bundle(dir).unwrap_or_else(|refusal| panic!("the bundle was refused: {refusal}"))
}

/// Run the real command, `tools/bundle`, with `args`.
fn tool(args: &[&OsStr]) -> Output {
    Command::new("bash")
        .arg(lane_dir().join("tools").join("bundle"))
        .args(args)
        .output()
        .expect("spawn tools/bundle")
}

/// `tools/bundle --name DIR`.
fn tool_name(dir: &Path) -> Output {
    tool(&[OsStr::new("--name"), dir.as_os_str()])
}

/// `tools/bundle OUT_DIR`: build, write OUT_DIR/bundle/, print its name.
fn tool_build(out_dir: &Path) -> Output {
    tool(&[out_dir.as_os_str()])
}

/// The one stdout line of a `tools/bundle` run that must succeed.
fn printed_name(output: Output) -> String {
    assert!(
        output.status.success(),
        "tools/bundle refused ({}):\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let line = stdout
        .strip_suffix('\n')
        .expect("tools/bundle prints one line");
    assert!(!line.contains('\n'), "tools/bundle prints only the name");
    line.to_string()
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

    // Their sha256 is pinned: the rule and the real command both give it.
    assert_eq!(lab_name(&files).expect("name the fixture"), FIXTURE_NAME);
    assert_eq!(
        printed_name(tool_name(&bundle)),
        FIXTURE_NAME,
        "tools/bundle --name must print the pinned name"
    );

    // The build mode reuses tools/build and prints the name of exactly the
    // closure it wrote, through the same rule.
    let out = tmp.path().join("out");
    let printed = printed_name(tool_build(&out));
    let written = out.join("bundle");
    assert_eq!(
        printed,
        name_of(&written),
        "tools/bundle must print the closure rule's name of the bundle it wrote"
    );
    assert_eq!(
        Receipt::read(&out).get("artifact_sha256"),
        sha256_file(&written.join("capsule.wasm")),
        "the bundle's module must be the artifact tools/build built and receipted"
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
    use std::time::{Duration, UNIX_EPOCH};

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
        lab_name(&listed).expect("name the listed order"),
        lab_name(&reversed).expect("name the reversed order"),
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
    assert!(
        refusal.reason.contains("is not part of the lab closure"),
        "the refusal must say why, got: {}",
        refusal.reason
    );

    // The command refuses it the same way and prints no name.
    let output = tool_name(&bundle);
    assert_eq!(output.status.code(), Some(1), "tools/bundle must refuse it");
    assert!(
        output.stdout.is_empty(),
        "a refused bundle must get no name"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "{}: is not part of the lab closure",
            extra.display()
        )),
        "tools/bundle must name the extra file and the reason, got:\n{stderr}"
    );
}

#[test]
fn a_missing_closure_file_is_refused() {
    let tmp = TempDir::new("bundle-missing");
    let bundle = fixture_bundle(tmp.path());
    fs::remove_file(bundle.join("capsule.wasm")).expect("remove the module");

    let refusal = name_bundle(&bundle).expect_err("a bundle without its module must be refused");
    assert_eq!(
        refusal.path,
        bundle.join("capsule.wasm"),
        "the refusal must name the missing file"
    );
    assert!(
        refusal.reason.contains("is missing from the lab closure"),
        "the refusal must say why, got: {}",
        refusal.reason
    );
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
    assert_eq!(
        refusal.reason, "is a symlink (a symlink is never followed, to read or to write)",
        "the refusal must say why"
    );
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
        refusal.reason, "is a symlink (a symlink is never followed, to read or to write)",
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
        lab_name(&files).expect("name the files"),
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
        refusal.reason,
        "is not a regular file (a directory, FIFO or device is never part of the lab closure)",
        "the refusal must say why"
    );
}

/// What a sentinel holds. A sentinel sits outside OUT_DIR, behind a link, and
/// must still hold exactly this after tools/bundle runs.
const SENTINEL: &[u8] = b"outside OUT_DIR: tools/bundle must never write here\n";

fn sentinel(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, SENTINEL).expect("write a sentinel");
    path
}

/// The run was refused at `path` for `reason`, and printed no name.
fn assert_refused(output: &Output, path: &Path, reason: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "tools/bundle must refuse, got:\n{stderr}"
    );
    assert!(output.stdout.is_empty(), "a refused run must print no name");
    assert!(
        stderr.contains(&format!("bundle: refused: {}: {reason}\n", path.display())),
        "tools/bundle must name {} and the reason, got:\n{stderr}",
        path.display()
    );
}

#[cfg(unix)]
#[test]
fn tools_bundle_never_writes_through_a_link() {
    use std::os::unix::fs::symlink;
    const BUNDLE_EXISTS: &str =
        "already exists (tools/bundle writes a new bundle, never into or through what is already there)";
    let tmp = TempDir::new("bundle-write-links");

    // A linked bundle directory, a symlink at tools/build's module output and a
    // hard link at its receipt output.
    let out = tmp.path().join("out");
    fs::create_dir(&out).expect("create OUT_DIR");
    let elsewhere = tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).expect("create the directory the bundle links to");
    symlink(&elsewhere, out.join("bundle")).expect("link OUT_DIR/bundle");
    let module_sentinel = sentinel(tmp.path(), "module-sentinel");
    let receipt_sentinel = sentinel(tmp.path(), "receipt-sentinel");
    symlink(&module_sentinel, out.join("capsule.wasm")).expect("link OUT_DIR/capsule.wasm");
    fs::hard_link(&receipt_sentinel, out.join("receipt.txt"))
        .expect("hard-link OUT_DIR/receipt.txt");

    let output = tool_build(&out);
    assert_eq!(
        fs::read(&module_sentinel).expect("read the module sentinel"),
        SENTINEL,
        "tools/build wrote OUT_DIR/capsule.wasm through its symlink"
    );
    assert_eq!(
        fs::read(&receipt_sentinel).expect("read the receipt sentinel"),
        SENTINEL,
        "tools/build wrote OUT_DIR/receipt.txt into the file its hard link shares"
    );
    assert_eq!(
        fs::read_dir(&elsewhere)
            .expect("list the linked directory")
            .count(),
        0,
        "tools/bundle wrote through the linked bundle directory"
    );
    // tools/build replaced both of its outputs with new files.
    assert!(
        fs::symlink_metadata(out.join("capsule.wasm"))
            .expect("inspect OUT_DIR/capsule.wasm")
            .file_type()
            .is_file(),
        "tools/build must replace the symlink at OUT_DIR/capsule.wasm with a new file"
    );
    assert_eq!(
        Receipt::read(&out).get("artifact_sha256"),
        sha256_file(&out.join("capsule.wasm")),
        "tools/build must write a new receipt for the module it built"
    );
    assert_refused(&output, &out.join("bundle"), BUNDLE_EXISTS);

    // A real bundle directory whose capsule.json links to a sentinel: refused
    // as it stands, and the sentinel is never written.
    let out = tmp.path().join("out-with-bundle");
    let bundle = out.join("bundle");
    fs::create_dir_all(&bundle).expect("create OUT_DIR/bundle");
    let manifest_sentinel = sentinel(tmp.path(), "manifest-sentinel");
    symlink(&manifest_sentinel, bundle.join("capsule.json")).expect("link capsule.json");

    let output = tool_build(&out);
    assert_eq!(
        fs::read(&manifest_sentinel).expect("read the manifest sentinel"),
        SENTINEL,
        "tools/bundle wrote capsule.json through its link"
    );
    assert_refused(&output, &bundle, BUNDLE_EXISTS);
}

/// The member `key` of a manifest object.
fn field<'a>(fields: &'a [(String, Value)], key: &str) -> &'a Value {
    &fields
        .iter()
        .find(|(name, _)| name == key)
        .unwrap_or_else(|| panic!("capsule.json has no `{key}` field"))
        .1
}

fn text(value: &str) -> Value {
    Value::String(value.to_string())
}

#[test]
fn bundle_manifest_matches_lab_schema() {
    let tmp = TempDir::new("bundle-schema");
    let out = tmp.path().join("out");
    printed_name(tool_build(&out));
    let bundle = out.join("bundle");
    let bytes = fs::read(bundle.join("capsule.json")).expect("read the written manifest");

    // The lab manifest schema, README.md "Lab manifest": exactly these fields,
    // these types, and this capsule's values.
    let manifest =
        json::parse(&bytes).unwrap_or_else(|why| panic!("capsule.json must be strict JSON: {why}"));
    let Value::Object(fields) = manifest else {
        panic!("capsule.json must be a JSON object");
    };
    let mut keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "entrypoint",
            "imports",
            "name",
            "resources",
            "schema",
            "version"
        ],
        "capsule.json must hold exactly the lab schema's fields"
    );
    assert_eq!(field(&fields, "schema"), &text("wc-003.lab-manifest/v1"));
    assert_eq!(field(&fields, "name"), &text(env!("CARGO_PKG_NAME")));
    assert_eq!(field(&fields, "version"), &text(env!("CARGO_PKG_VERSION")));
    assert_eq!(
        field(&fields, "entrypoint"),
        &text("capsule.wasm"),
        "the entrypoint is the closure's core Wasm module"
    );
    assert!(
        bundle.join("capsule.wasm").is_file(),
        "the entrypoint must name a file in the closure"
    );
    assert_eq!(
        field(&fields, "imports"),
        &Value::Array(Vec::new()),
        "the zero-import capsule declares no imports"
    );
    assert_eq!(
        field(&fields, "resources"),
        &Value::Object(vec![("max_memory_pages".to_string(), Value::Integer(16))]),
        "the memory ceiling is 16 Wasm pages of 64 KiB (1 MiB)"
    );
}

#[test]
fn bundle_output_uses_the_lab_name_prefix() {
    let tmp = TempDir::new("bundle-prefix");
    let bundle = fixture_bundle(tmp.path());
    let printed = printed_name(tool_name(&bundle));

    let digest = printed.strip_prefix("lab-sha256:").unwrap_or_else(|| {
        panic!("tools/bundle must label its name `lab-sha256:`, got {printed:?}")
    });
    assert!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "a lab name is 64 lowercase hex digits after its label, got {printed:?}"
    );
    let lower = printed.to_ascii_lowercase();
    assert!(
        !lower.contains("cid") && !lower.contains("bafy"),
        "a lab name must never be called or look like a CID, got {printed:?}"
    );
}
