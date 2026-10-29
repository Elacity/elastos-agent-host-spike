//! The walk reads only handles it has checked. Each swap test changes
//! web-app while it is named, at one of the walk's two moments. A temp folder
//! outside the bundle holds files with the same names but other bytes, plus
//! one extra file, so a walk that follows a link, or reads or lists by path
//! after its check, names those bytes or meets the extra file.
mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use capsule_identity::{lab_cid, Moment, Refusal};
use common::*;
use tempfile::TempDir;

/// What every swap test starts from: web-app assembled in a temp dir, the
/// outside folder, and a temp folder that takes what a swap moves out of the
/// bundle.
struct Swap {
    bundle: TempDir,
    outside: TempDir,
    moved: TempDir,
}

impl Swap {
    fn new() -> Self {
        Swap {
            bundle: assemble(&WEB_APP),
            outside: outside_browser(),
            moved: temp_dir(),
        }
    }

    /// The change that moves browser/app.js out of the bundle and puts a
    /// link to the outside app.js in its place.
    fn app_js_for_an_outside_link(&self) -> impl FnOnce() + Send + 'static {
        let entry = self.bundle.path().join("browser/app.js");
        let target = self.outside.path().join("app.js");
        let moved = self.moved.path().join("app.js");
        move || {
            fs::rename(&entry, &moved).expect("move browser/app.js out");
            symlink(&target, &entry).expect("link browser/app.js outside");
        }
    }
}

/// Whether `path` itself is a link, so a test can show its swap ran.
fn is_link(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}

#[test]
fn entry_swapped_for_a_link_before_open_is_refused() {
    // browser/app.js is listed as a regular file. Before the walk opens it,
    // it becomes a link to the outside app.js, so only the no-follow open
    // keeps the walk from reading the outside bytes.
    let swap = Swap::new();
    let entry = swap.bundle.path().join("browser/app.js");
    let target = swap.outside.path().join("app.js");
    let refusal = lab_cid_bounded(
        swap.bundle.path(),
        at(Moment::BeforeOpen, "browser/app.js", move || {
            fs::remove_file(&entry).expect("remove browser/app.js");
            symlink(&target, &entry).expect("link browser/app.js outside");
        }),
    )
    .expect_err("a link swapped in before the open gets no name");
    assert_eq!(
        refusal.to_string(),
        "browser/app.js is a symbolic link: the lab CID covers only regular files and never follows a link"
    );
    assert_eq!(
        refusal,
        Refusal::NotRegularFile {
            path: "browser/app.js".into(),
            kind: "symbolic link"
        }
    );
}

#[test]
fn entry_swapped_for_a_fifo_before_open_is_refused_without_blocking() {
    // browser/app.js becomes a FIFO before the walk opens it. An open that
    // waits would wait for a writer that never comes; BOUND catches that.
    let swap = Swap::new();
    let entry = swap.bundle.path().join("browser/app.js");
    let refusal = lab_cid_bounded(
        swap.bundle.path(),
        at(Moment::BeforeOpen, "browser/app.js", move || {
            fs::remove_file(&entry).expect("remove browser/app.js");
            make_fifo(&entry);
        }),
    )
    .expect_err("a FIFO swapped in before the open gets no name");
    assert_eq!(
        refusal.to_string(),
        "browser/app.js is a FIFO: the lab CID covers only regular files and never follows a link"
    );
    assert_eq!(
        refusal,
        Refusal::NotRegularFile {
            path: "browser/app.js".into(),
            kind: "FIFO"
        }
    );
}

#[test]
fn entry_swapped_for_a_folder_before_open_is_refused() {
    // browser/app.js becomes a folder before the walk opens it. A folder may
    // be in a bundle, so only the check against the listed kind refuses it.
    let swap = Swap::new();
    let entry = swap.bundle.path().join("browser/app.js");
    let outside_app = swap.outside.path().join("app.js");
    let refusal = lab_cid_bounded(
        swap.bundle.path(),
        at(Moment::BeforeOpen, "browser/app.js", move || {
            fs::remove_file(&entry).expect("remove browser/app.js");
            fs::create_dir(&entry).expect("make browser/app.js a folder");
            fs::copy(&outside_app, entry.join("app.js")).expect("fill the folder");
        }),
    )
    .expect_err("an entry that changed kind before the open gets no name");
    assert_eq!(
        refusal.to_string(),
        "browser/app.js changed while the bundle was named"
    );
    assert_eq!(
        refusal,
        Refusal::Changed {
            path: "browser/app.js".into()
        }
    );
}

#[test]
fn entry_swapped_after_its_handle_is_checked_names_the_checked_bytes() {
    // After the walk has checked browser/app.js's handle, the file moves out
    // of the bundle and a link to the outside app.js takes its place. The
    // walk reads the handle it checked, so the name is web-app's.
    let swap = Swap::new();
    let entry = swap.bundle.path().join("browser/app.js");
    let change = swap.app_js_for_an_outside_link();
    let named = lab_cid_bounded(
        swap.bundle.path(),
        at(Moment::AfterCheck, "browser/app.js", change),
    )
    .unwrap_or_else(|refusal| panic!("a swap after the check must not stop the walk: {refusal}"));
    assert!(is_link(&entry), "the swap did not run during the walk");
    assert_eq!(named.to_string(), WEB_APP_LAB_CID);
}

#[test]
fn checked_entries_are_the_bytes_the_walk_checked() {
    // The same swap, on the checked bundle. The value keeps the bytes the
    // checked handle held: its lab CID is web-app's, and its browser/app.js
    // entry holds web-app's bytes, never the outside file's. A seam that read
    // the entries again by path after the walk would follow the link.
    let swap = Swap::new();
    let entry = swap.bundle.path().join("browser/app.js");
    let outside_app =
        fs::read(swap.outside.path().join("app.js")).expect("read the outside app.js");
    let web_app = read_fixture(&WEB_APP, "browser/app.js");
    assert_ne!(
        outside_app, web_app,
        "the outside app.js must hold other bytes"
    );
    let change = swap.app_js_for_an_outside_link();
    let value = checked_bundle_bounded(
        swap.bundle.path(),
        at(Moment::AfterCheck, "browser/app.js", change),
    )
    .unwrap_or_else(|refusal| panic!("a swap after the check must not stop the walk: {refusal}"));
    assert!(is_link(&entry), "the swap did not run during the walk");
    assert_eq!(value.cid().to_string(), WEB_APP_LAB_CID);
    let app = value
        .entries()
        .iter()
        .find(|entry| entry.path == "browser/app.js")
        .expect("the checked bundle holds browser/app.js");
    assert_ne!(
        app.content, outside_app,
        "browser/app.js holds the outside file's bytes, which its lab CID does not name"
    );
    assert_eq!(
        app.content, web_app,
        "browser/app.js does not hold the bytes its checked handle held"
    );
}

#[test]
fn folder_swapped_after_its_handle_is_checked_names_the_checked_bytes() {
    // After the walk has checked browser's handle, the folder moves out of
    // the bundle and a link to the outside folder takes its place. The walk
    // lists the handle it checked and opens each entry relative to it, so the
    // name is web-app's: never the outside bytes or the extra file.
    let swap = Swap::new();
    let folder = swap.bundle.path().join("browser");
    let change = {
        let folder = folder.clone();
        let target = swap.outside.path().to_path_buf();
        let moved = swap.moved.path().join("browser");
        move || {
            fs::rename(&folder, &moved).expect("move browser/ out");
            symlink(&target, &folder).expect("link browser outside");
        }
    };
    let named = lab_cid_bounded(
        swap.bundle.path(),
        at(Moment::AfterCheck, "browser", change),
    )
    .unwrap_or_else(|refusal| panic!("a swap after the check must not stop the walk: {refusal}"));
    assert!(is_link(&folder), "the swap did not run during the walk");
    assert_eq!(named.to_string(), WEB_APP_LAB_CID);
}

#[test]
fn dot_entries_are_skipped() {
    // Every folder's listing holds `.` (the folder) and `..` (its parent).
    // Opening `.` walks the same folder again forever; opening `..` climbs out
    // of the bundle. The observer stops the walk before either is opened.
    let bundle = assemble(&WEB_APP);
    let named = lab_cid_bounded(bundle.path(), |moment, path| {
        let name = path.rsplit('/').next().unwrap_or(path);
        assert!(
            moment != Moment::BeforeOpen || !matches!(name, "." | ".."),
            "the walk was about to open {path}"
        );
    })
    .unwrap_or_else(|refusal| panic!("{refusal}"));
    assert_eq!(named.to_string(), WEB_APP_LAB_CID);
}

#[test]
fn link_at_the_bundle_root_is_refused() {
    // The root path is opened once, as a folder, with no-follow: a link as
    // its last part is refused, never followed. The same folder named by its
    // own path gets its name.
    let bundle = assemble(&WEB_APP);
    let links = temp_dir();
    let root = links.path().join("web-app");
    symlink(bundle.path(), &root).expect("link the bundle root");
    let named = lab_cid(bundle.path()).unwrap_or_else(|refusal| panic!("{refusal}"));
    assert_eq!(named.to_string(), WEB_APP_LAB_CID);

    let refusal = lab_cid(&root).expect_err("a link at the root path is not followed");
    assert!(
        matches!(&refusal, Refusal::Unreadable { path, .. } if path == "."),
        "{refusal}"
    );
    assert!(
        refusal.to_string().starts_with("could not read .: "),
        "{refusal}"
    );
}

#[test]
fn root_path_through_a_link_loop_keeps_the_system_reason() {
    // A link that points at itself sits above the root, so the root path
    // never resolves. Only an entry's own open can mean "this is a link";
    // here the refusal keeps the system's reason and does not call the root
    // a link.
    let parent = temp_dir();
    symlink("loop", parent.path().join("loop")).expect("make a link loop");
    let refusal = lab_cid(&parent.path().join("loop/web-app"))
        .expect_err("a root path that never resolves gets no name");
    assert!(
        matches!(&refusal, Refusal::Unreadable { path, .. } if path == "."),
        "{refusal}"
    );
    assert_eq!(
        refusal.to_string(),
        format!(
            "could not read .: {}",
            std::io::Error::from(rustix::io::Errno::LOOP)
        )
    );
}

#[test]
fn lab_cid_and_the_seam_run_one_walk() {
    // P10: one walk names a bundle. lab_cid is the seam's walk with an
    // observer that does nothing, and the library lists a folder, opens an
    // entry and checks a handle in one place each. It reaches no file by a
    // path, so no second walk can hide beside the checked one.
    let code = library_code();
    assert!(
        code.contains(
            "pub fn lab_cid(bundle: &Path) -> Result<LabCid, Refusal> {\n    lab_cid_observed(bundle, |_, _| {})\n}"
        ),
        "lab_cid is not the seam's walk with an observer that does nothing"
    );
    // The walk's definition and its one call.
    assert_eq!(
        code.matches("collect_entries(").count(),
        2,
        "collect_entries"
    );
    for call in ["Dir::read_from(", "openat(", "fstat("] {
        assert_eq!(code.matches(call).count(), 1, "{call} is not in one place");
    }
    for call in [
        "fs::read",
        "read_dir",
        "metadata",
        "File::open",
        "OpenOptions",
        "canonicalize",
    ] {
        assert!(
            !code.contains(call),
            "the library reaches a file by path: {call}"
        );
    }
}
