//! Pack: a capsule's closure out of its source folder (capsule kit item 3).

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use capsule_bundle::testing::refused;
use capsule_bundle::*;

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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
    let root = tempfile::tempdir().unwrap();
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
