//! Pack: a capsule's closure out of its source folder (capsule kit item 3).

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use capsule_bundle::testing::refused;
use capsule_bundle::*;

/// A temporary folder named by its real path. On macOS the system's temporary
/// folder is under a link (`/var` is `/private/var`), and the bundle tool
/// refuses a path through a link.
struct Temp(#[allow(dead_code)] tempfile::TempDir, PathBuf);

impl Temp {
    fn path(&self) -> &Path {
        &self.1
    }
}

fn tempdir() -> Temp {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().canonicalize().unwrap();
    Temp(dir, real)
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn manifest(execution: &str, entrypoint: &str) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "schema": "elastos.capsule/v1",
        "name": "x",
        "version": "0.1.0",
        "role": if execution == "component" { "app" } else { "viewer" },
        "execution": execution,
        "entrypoint": entrypoint,
        "requires": [{ "name": "storage", "kind": "provider" }],
    }))
    .unwrap()
}

/// A component source folder: its manifest, its artifact, and what does not ship.
fn component_source(root: &Path) -> PathBuf {
    let dir = root.join("core");
    write(
        &dir.join("capsule.json"),
        &manifest("component", "x.component.wasm"),
    );
    write(&dir.join("x.component.wasm"), b"\0asm component");
    write(&dir.join("src/lib.rs"), b"fn main() {}");
    write(&dir.join("target/release/x.wasm"), b"\0asm core");
    write(&dir.join("README.md"), b"# x");
    dir
}

/// A page source folder: its manifest, its browser folder, and its tests.
fn page_source(root: &Path) -> PathBuf {
    let dir = root.join("page");
    write(
        &dir.join("capsule.json"),
        &manifest("web-projection", "browser/index.html"),
    );
    write(&dir.join("browser/index.html"), b"<!doctype html>");
    write(&dir.join("browser/main.js"), b"// main");
    write(&dir.join("browser/styles/page.css"), b"main {}");
    write(&dir.join("page.test.mjs"), b"// tests");
    write(&dir.join("fixtures/out.json"), b"{}");
    dir
}

fn paths(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|entry| entry.path.as_str()).collect()
}

#[test]
fn a_component_ships_its_manifest_and_its_entrypoint_only() {
    let root = tempdir();
    let source = component_source(root.path());
    let into = root.path().join("packed");
    let (cid, entries) = pack(&source, &into, &[]).unwrap();
    assert_eq!(paths(&entries), ["capsule.json", "x.component.wasm"]);
    assert_eq!(closure_cid(&into).unwrap().0, cid);
    // Without requirements the manifest is the source's, byte for byte.
    assert_eq!(
        std::fs::read(into.join("capsule.json")).unwrap(),
        std::fs::read(source.join("capsule.json")).unwrap()
    );
}

#[test]
fn a_page_ships_its_manifest_and_its_entrypoint_folder() {
    let root = tempdir();
    let (_, entries) = pack(&page_source(root.path()), &root.path().join("packed"), &[]).unwrap();
    assert_eq!(
        paths(&entries),
        [
            "browser/index.html",
            "browser/main.js",
            "browser/styles/page.css",
            "capsule.json"
        ]
    );
}

#[test]
fn the_cid_does_not_change_when_a_test_source_or_fixture_does() {
    let root = tempdir();
    let page = page_source(root.path());
    let (first, _) = pack(&page, &root.path().join("one"), &[]).unwrap();
    write(&page.join("page.test.mjs"), b"// other tests");
    write(&page.join("fixtures/out.json"), b"{\"other\":1}");
    let (second, _) = pack(&page, &root.path().join("two"), &[]).unwrap();
    assert_eq!(first, second);
    // What ships does change it.
    write(&page.join("browser/main.js"), b"// other main");
    let (third, _) = pack(&page, &root.path().join("three"), &[]).unwrap();
    assert_ne!(first, third);
}

#[test]
fn a_page_names_its_core_by_cid_and_keeps_its_other_requirements() {
    let root = tempdir();
    let core = component_source(root.path());
    let (core_cid, _) = pack(&core, &root.path().join("core-packed"), &[]).unwrap();
    let page = page_source(root.path());
    let into = root.path().join("page-packed");
    pack(&page, &into, &[("x-core".to_string(), core_cid.clone())]).unwrap();
    let shipped: serde_json::Value =
        serde_json::from_slice(&std::fs::read(into.join("capsule.json")).unwrap()).unwrap();
    assert_eq!(
        shipped["requires"],
        serde_json::json!([
            { "name": "storage", "kind": "provider" },
            { "name": "x-core", "kind": "capsule", "cid": core_cid },
        ])
    );
    let installed = [Installed {
        name: "x-core".into(),
        version: "0.1.0".into(),
        cid: core_cid,
    }];
    assert_eq!(resolve_requires(&shipped, &installed).unwrap(), installed);
    // A second pack with another core replaces the requirement, never adds one.
    let again = root.path().join("page-again");
    let other = format!("b{}", "a".repeat(58));
    pack(&into, &again, &[("x-core".to_string(), other.clone())]).unwrap();
    let shipped: serde_json::Value =
        serde_json::from_slice(&std::fs::read(again.join("capsule.json")).unwrap()).unwrap();
    assert_eq!(shipped["requires"][1]["cid"], other);
    assert_eq!(shipped["requires"].as_array().unwrap().len(), 2);
}

#[test]
fn pack_refuses_what_it_cannot_ship_as_it_is() {
    let root = tempdir();
    let r = root.path();

    // No manifest; no entrypoint; an entrypoint that is not built.
    std::fs::create_dir_all(r.join("empty")).unwrap();
    assert_eq!(
        refused(pack(&r.join("empty"), &r.join("o1"), &[])),
        "manifest_missing"
    );
    let core = component_source(r);
    std::fs::remove_file(core.join("x.component.wasm")).unwrap();
    assert_eq!(
        refused(pack(&core, &r.join("o2"), &[])),
        "pack_entrypoint_missing"
    );
    write(&core.join("capsule.json"), b"{\"name\":\"x\"}");
    assert_eq!(
        refused(pack(&core, &r.join("o3"), &[])),
        "pack_entrypoint_missing"
    );

    // An entrypoint that leaves the folder, or a page at the root.
    write(
        &core.join("capsule.json"),
        &manifest("component", "../x.component.wasm"),
    );
    assert_eq!(refused(pack(&core, &r.join("o4"), &[])), "path_invalid");
    let page = page_source(r);
    write(
        &page.join("capsule.json"),
        &manifest("web-projection", "index.html"),
    );
    write(&page.join("index.html"), b"<!doctype html>");
    assert_eq!(
        refused(pack(&page, &r.join("o5"), &[])),
        "pack_entrypoint_missing"
    );

    // Links are refused, never followed: in a page folder, or as the entrypoint.
    let page = r.join("page-link");
    std::fs::rename(page_source(&r.join("p2")), &page).unwrap();
    symlink("/etc/hostname", page.join("browser/leak.txt")).unwrap();
    assert_eq!(refused(pack(&page, &r.join("o6"), &[])), "special_file");
    let core = r.join("core-link");
    std::fs::rename(component_source(&r.join("c2")), &core).unwrap();
    std::fs::remove_file(core.join("x.component.wasm")).unwrap();
    symlink(core.join("README.md"), core.join("x.component.wasm")).unwrap();
    assert_eq!(refused(pack(&core, &r.join("o7"), &[])), "special_file");

    // A destination that exists, and a core named by something that is not a CID.
    let core = component_source(&r.join("c3"));
    std::fs::create_dir_all(r.join("taken")).unwrap();
    assert_eq!(
        refused(pack(&core, &r.join("taken"), &[])),
        "pack_destination_exists"
    );
    let requires = [("x-core".to_string(), "../not-a-cid".to_string())];
    assert_eq!(
        refused(pack(&core, &r.join("o8"), &requires)),
        "path_invalid"
    );
}

#[test]
fn pack_refuses_a_symlinked_folder_anywhere_on_the_path() {
    let root = tempdir();
    let r = root.path();
    // Bytes outside the source that a followed link would ship.
    write(&r.join("outside/payload.component.wasm"), b"\0asm outside");
    write(
        &r.join("outside/browser/index.html"),
        b"<!doctype html> outside",
    );
    write(&r.join("outside/deep/c/x.component.wasm"), b"\0asm outside");
    let shipped_nothing = |into: &Path| assert!(!into.exists(), "{} was written", into.display());

    // Codex's case: the entrypoint under a linked folder (component).
    let core = component_source(&r.join("c1"));
    symlink("../../outside", core.join("linked")).unwrap();
    write(
        &core.join("capsule.json"),
        &manifest("component", "linked/payload.component.wasm"),
    );
    assert_eq!(refused(pack(&core, &r.join("o1"), &[])), "symlink_in_path");
    shipped_nothing(&r.join("o1"));

    // The same for a page: its folder is under a linked folder.
    let page = page_source(&r.join("p1"));
    symlink("../../outside", page.join("linked")).unwrap();
    write(
        &page.join("capsule.json"),
        &manifest("web-projection", "linked/browser/index.html"),
    );
    assert_eq!(refused(pack(&page, &r.join("o2"), &[])), "symlink_in_path");
    shipped_nothing(&r.join("o2"));

    // A link in the middle of a path: a/b is a link, a and c are real.
    let core = component_source(&r.join("c2"));
    std::fs::create_dir_all(core.join("a")).unwrap();
    symlink("../../../outside/deep", core.join("a/b")).unwrap();
    write(
        &core.join("capsule.json"),
        &manifest("component", "a/b/c/x.component.wasm"),
    );
    assert_eq!(refused(pack(&core, &r.join("o3"), &[])), "symlink_in_path");
    shipped_nothing(&r.join("o3"));

    // A page's own folder is a link (the last folder of its entrypoint).
    let page = page_source(&r.join("p2"));
    std::fs::remove_dir_all(page.join("browser")).unwrap();
    symlink("../../outside/browser", page.join("browser")).unwrap();
    assert_eq!(refused(pack(&page, &r.join("o4"), &[])), "symlink_in_path");
    shipped_nothing(&r.join("o4"));

    // The source folder itself is a link.
    let core = component_source(&r.join("c3"));
    symlink(&core, r.join("core-alias")).unwrap();
    assert_eq!(
        refused(pack(&r.join("core-alias"), &r.join("o5"), &[])),
        "symlink_in_path"
    );
    shipped_nothing(&r.join("o5"));

    // Without the links, the same layouts pack (the refusals are the links).
    let core = component_source(&r.join("c4"));
    write(&core.join("a/b/c/x.component.wasm"), b"\0asm inside");
    write(
        &core.join("capsule.json"),
        &manifest("component", "a/b/c/x.component.wasm"),
    );
    let (_, entries) = pack(&core, &r.join("o6"), &[]).unwrap();
    assert_eq!(paths(&entries), ["a/b/c/x.component.wasm", "capsule.json"]);
}

#[test]
fn a_symlinked_root_is_refused_however_its_path_is_written() {
    let root = tempdir();
    let r = root.path();
    let core = component_source(r);
    // root-link -> core, a valid capsule folder; a/link -> the temporary
    // folder, so a/./link/core reaches the same capsule through a link.
    symlink(&core, r.join("root-link")).unwrap();
    std::fs::create_dir_all(r.join("a")).unwrap();
    symlink(r, r.join("a/link")).unwrap();

    // Relative paths, as a shell gives them; nothing else in this file uses
    // the current folder.
    let back = std::env::current_dir().unwrap();
    std::env::set_current_dir(r).unwrap();
    let spellings = [
        "root-link/",
        "root-link/.",
        "root-link//",
        "./root-link/",
        "a/./link/core",
    ];
    let mut outcome = Vec::new();
    for (n, spelling) in spellings.iter().enumerate() {
        let into = r.join(format!("out{n}"));
        outcome.push((
            *spelling,
            refused(pack(Path::new(spelling), &into, &[])).to_string(),
            refused(list_closure(Path::new(spelling))).to_string(),
            into.exists(),
        ));
    }
    // Written without a link, the same folder packs and lists.
    let fine = pack(Path::new("./core/."), &r.join("fine"), &[]).map(|(cid, _)| cid);
    let listed = list_closure(Path::new("core/")).map(|entries| entries.len());
    let parent = refused(pack(Path::new("a/../core"), &r.join("up"), &[])).to_string();
    let empty = refused(list_closure(Path::new(""))).to_string();
    std::env::set_current_dir(back).unwrap();

    for (spelling, packed, listed, written) in outcome {
        assert_eq!(packed, "symlink_in_path", "pack {spelling}");
        assert_eq!(listed, "symlink_in_path", "listing {spelling}");
        assert!(!written, "pack {spelling} wrote its output");
    }
    assert!(fine.is_ok(), "{fine:?}");
    assert_eq!(listed.unwrap(), list_closure(&core).unwrap().len());
    assert_eq!(parent, "path_invalid");
    assert_eq!(empty, "path_invalid");
}

#[test]
fn pack_refuses_a_symlinked_destination_before_writing() {
    let root = tempdir();
    let r = root.path();
    let core = component_source(r);
    std::fs::create_dir_all(r.join("real")).unwrap();
    symlink(r.join("real"), r.join("alias")).unwrap();

    // The destination's parent is a link: refused before the first write, so
    // the folder is not made either here (through the link) or at its target.
    let through_link = r.join("alias/out");
    let refusal = pack(&core, &through_link, &[]).unwrap_err();
    assert_eq!(refusal.code(), "symlink_in_path");
    assert!(
        !through_link.exists(),
        "{} was written",
        through_link.display()
    );
    assert!(
        !r.join("real/out").exists(),
        "{} was written",
        r.join("real/out").display()
    );
    // The refusal says how to recover: give the physical path, not the link.
    let message = refusal.to_string();
    assert!(message.starts_with("symlink_in_path: "), "{message}");
    assert!(message.contains("physical path"), "{message}");

    // The same pack into the physical folder works, so the retry after the
    // refusal is not `pack_destination_exists`.
    let into = r.join("real/out");
    let (cid, entries) = pack(&core, &into, &[]).unwrap();
    assert_eq!(paths(&entries), ["capsule.json", "x.component.wasm"]);
    assert_eq!(closure_cid(&into).unwrap().0, cid);
}

#[test]
fn pack_writes_a_new_destination_at_every_level_it_names() {
    let root = tempdir();
    let r = root.path();
    let core = component_source(r);
    std::fs::create_dir_all(r.join("existing")).unwrap();

    // Two new levels below an existing folder: the destination is the whole
    // path, not the part up to its first missing folder.
    let into = r.join("existing/a/b");
    let (cid, entries) = pack(&core, &into, &[]).unwrap();
    assert_eq!(paths(&entries), ["capsule.json", "x.component.wasm"]);
    assert!(
        into.join("capsule.json").is_file(),
        "{} has no manifest",
        into.display()
    );
    assert!(into.join("x.component.wasm").is_file());
    assert!(
        !r.join("existing/a/capsule.json").exists(),
        "{} was written",
        r.join("existing/a").display()
    );
    assert_eq!(closure_cid(&into).unwrap().0, cid);
}
