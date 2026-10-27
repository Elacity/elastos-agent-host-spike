//! This test code stands in for the Runtime's launch by CID, which does not exist yet.
//! PH6 packs, resolves and loads passive content. It starts no component.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use capsule_bundle::testing::unseal;
use capsule_bundle::{load, pack, resolve_requires, validate_content_stand_in, Installed, Refusal};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FILES: [&str; 4] = [
    "capsule.json",
    "images/01.png",
    "images/02.jpg",
    "images/03.webp",
];

struct World {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl World {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        Self { _temp: temp, root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn content(&self) -> PathBuf {
        let source = self.path("content-source");
        let fixture = photo_dir().join("host-test/fixtures/stand-in-photo-set");
        for path in FILES.into_iter().chain(["README.md"]) {
            write(
                &source.join(path),
                &std::fs::read(fixture.join(path)).unwrap(),
            );
        }
        source
    }

    // Two real closure identities per name; these bytes are packing inputs,
    // not a claim of component execution or publisher admission.
    fn dependencies(&self) -> (Vec<Installed>, Value) {
        let mut installed = Vec::new();
        let mut pinned_surface = Value::Null;
        for version in ["0.1.0", "0.2.0"] {
            let core_source = self.path(&format!("core-source-{version}"));
            write_manifest(
                &core_source,
                &json!({
                    "schema": "elastos.capsule/v1", "name": "photo-viewer", "version": version,
                    "role": "app", "execution": "component", "entrypoint": "core.wasm"
                }),
            );
            write(
                &core_source.join("core.wasm"),
                b"stand-in packing input; never executed",
            );
            let (core_cid, _) =
                pack(&core_source, &self.path(&format!("core-{version}")), &[]).unwrap();
            let surface = self.path(&format!("surface-{version}"));
            pack(
                &photo_dir().join("surface"),
                &surface,
                &[("photo-viewer".into(), core_cid.clone())],
            )
            .unwrap();
            pinned_surface = manifest_of(&surface);
            pinned_surface["version"] = json!(version);
            write_manifest(&surface, &pinned_surface);
            let (viewer_cid, _) = capsule_bundle::closure_cid(&surface).unwrap();
            installed.push(Installed {
                name: "photo-viewer".into(),
                version: version.into(),
                cid: core_cid,
            });
            installed.push(Installed {
                name: "image-viewer".into(),
                version: version.into(),
                cid: viewer_cid,
            });
        }
        (installed, pinned_surface)
    }
}

impl Drop for World {
    fn drop(&mut self) {
        unseal(&self.root);
    }
}

fn photo_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

fn write_manifest(source: &Path, manifest: &Value) {
    write(
        &source.join("capsule.json"),
        &serde_json::to_vec_pretty(manifest).unwrap(),
    );
}

fn manifest_of(source: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(source.join("capsule.json")).unwrap()).unwrap()
}

fn binding_refusal(refusal: Refusal, cid: &str, detail: &str) {
    assert_eq!(refusal.code(), "content_binding_invalid");
    assert_eq!(refusal.to_string(), format!(
        "content_binding_invalid: Content {cid} needs the passive photo profile and one viewer CID: {detail}."
    ));
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_load_names_an_absent_content_cid() {
    let world = World::new();
    let store = world.path("store");
    std::fs::create_dir(&store).unwrap();
    let cid = capsule_bundle::cid_v1_raw_sha256(b"absent stand-in content");
    let refusal = load(&store, &cid).unwrap_err();
    assert_eq!(refusal, Refusal::StagedMissing { cid: cid.clone() });
    assert_eq!(refusal.code(), "staged_missing");
    assert_eq!(refusal.to_string(), format!(
        "staged_missing: Content CID {cid} is absent from the staged store; admit that exact capsule first."
    ));

    let empty = store.join(&cid);
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o555)).unwrap();
    assert_eq!(load(&store, &cid).unwrap_err(), Refusal::ManifestMissing);

    // ENOTDIR is an I/O error, distinct from an absent staged root.
    let file = world.path("store-file");
    write(&file, b"a file cannot be a store");
    assert_eq!(load(&file, &cid).unwrap_err().code(), "io");
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_load_keeps_the_bytes_it_hashed() {
    let world = World::new();
    let source = world.content();
    let packed = world.path("packed");
    let (cid, entries) = pack(&source, &packed, &[]).unwrap();
    let store = world.path("store");
    std::fs::create_dir(&store).unwrap();
    let staged = store.join(&cid);
    std::fs::rename(&packed, &staged).unwrap();
    for path in FILES {
        std::fs::set_permissions(staged.join(path), std::fs::Permissions::from_mode(0o444))
            .unwrap();
    }
    for path in [staged.join("images"), staged.clone()] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555)).unwrap();
    }

    let loaded = load(&store, &cid).unwrap();
    assert_eq!(loaded.entries, entries);
    assert_eq!(loaded.bytes.len(), entries.len());
    for entry in &loaded.entries {
        let bytes = loaded
            .bytes
            .get(&entry.path)
            .expect("every listed file is kept");
        assert_eq!(entry.sha256, hex::encode(Sha256::digest(bytes)));
        assert_eq!(entry.size, bytes.len() as u64);
        assert_eq!(*bytes, std::fs::read(source.join(&entry.path)).unwrap());
    }
    let snapshot = loaded.bytes.clone();
    let image = staged.join("images/01.png");
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&image, b"changed staged image").unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert_ne!(std::fs::read(&image).unwrap(), snapshot["images/01.png"]);
    assert_eq!(loaded.bytes, snapshot);
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_pack_ships_the_complete_photo_set() {
    let world = World::new();
    let source = world.content();
    let into = world.path("packed");
    let (cid, entries) = pack(&source, &into, &[]).unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        FILES
    );
    for path in FILES {
        assert_eq!(
            std::fs::read(into.join(path)).unwrap(),
            std::fs::read(source.join(path)).unwrap()
        );
    }
    assert!(!into.join("README.md").exists());
    // Exercise the public CLI too, using the same packer.
    let cli = world.path("cli-packed");
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_capsule-bundle"))
        .args(["pack"])
        .arg(&source)
        .arg(&cli)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(capsule_bundle::closure_cid(&cli).unwrap(), (cid, entries));
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_content_cid_covers_payload_and_viewer_only() {
    let world = World::new();
    let source = world.content();
    let first = pack(&source, &world.path("first"), &[]).unwrap().0;
    write(&source.join("README.md"), b"changed source provenance");
    let readme = pack(&source, &world.path("readme"), &[]).unwrap().0;
    assert_eq!(first, readme, "source README is outside the closure");
    let image = source.join("images/02.jpg");
    let original = std::fs::read(&image).unwrap();
    write(
        &image,
        &[original.as_slice(), b"changed image bytes"].concat(),
    );
    assert_ne!(first, pack(&source, &world.path("image"), &[]).unwrap().0);
    write(&image, &original);
    let mut manifest = manifest_of(&source);
    manifest["viewer"]["cid"] = json!(capsule_bundle::cid_v1_raw_sha256(b"another viewer"));
    write_manifest(&source, &manifest);
    let viewer = pack(&source, &world.path("viewer"), &[]).unwrap().0;
    assert_ne!(first, viewer);
    // Even a byte-only manifest edit changes identity.
    let bytes = std::fs::read(source.join("capsule.json")).unwrap();
    write(
        &source.join("capsule.json"),
        &[bytes.as_slice(), b"\n"].concat(),
    );
    assert_ne!(
        viewer,
        pack(&source, &world.path("manifest"), &[]).unwrap().0
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_content_pack_preserves_path_safety() {
    use std::os::unix::fs::symlink;
    // Each link targets real, readable fixture bytes. A following walk/copy
    // would succeed, so downstream missing-file errors cannot hide the bug.
    for (case, code) in [
        ("file", "special_file"),
        ("folder", "special_file"),
        ("payload", "symlink_in_path"),
        ("entrypoint-folder", "pack_entrypoint_missing"),
        ("fifo", "special_file"),
    ] {
        let world = World::new();
        let source = world.content();
        let outside = world.path("outside");
        write(&outside.join("extra.png"), b"outside fixture bytes");
        match case {
            "file" => symlink(outside.join("extra.png"), source.join("images/extra.png")).unwrap(),
            "folder" => symlink(&outside, source.join("images/more")).unwrap(),
            "payload" => {
                std::fs::rename(source.join("images"), world.path("real-images")).unwrap();
                symlink(world.path("real-images"), source.join("images")).unwrap();
            }
            "entrypoint-folder" => {
                std::fs::remove_file(source.join("images/01.png")).unwrap();
                std::fs::create_dir(source.join("images/01.png")).unwrap();
            }
            "fifo" => {
                use std::os::unix::ffi::OsStrExt;
                let path = source.join("images/pipe");
                let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let into = world.path("packed");
        let refusal = pack(&source, &into, &[]).unwrap_err();
        assert_eq!(refusal.code(), code, "{case}: {refusal}");
        assert!(!into.exists(), "{case} left an output");
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_content_and_surface_resolve_by_exact_cid() {
    let world = World::new();
    let (installed, surface) = world.dependencies();
    let source = world.content();
    let mut manifest = manifest_of(&source);
    manifest["viewer"]["cid"] = json!(installed[3].cid);
    write_manifest(&source, &manifest);
    let cid = pack(&source, &world.path("packed"), &[]).unwrap().0;
    assert_ne!(installed[0].cid, installed[2].cid);
    assert_ne!(installed[1].cid, installed[3].cid);
    assert_eq!(
        resolve_requires((&manifest, cid.as_str()), &installed).unwrap(),
        vec![installed[3].clone()]
    );
    assert_eq!(
        resolve_requires(&surface, &installed).unwrap(),
        vec![installed[2].clone()]
    );
    // Inventory order is irrelevant. The name remains a metadata assertion.
    let reverse: Vec<_> = installed.iter().cloned().rev().collect();
    assert_eq!(
        resolve_requires((&manifest, cid.as_str()), &reverse).unwrap(),
        vec![installed[3].clone()]
    );
    manifest["viewer"]["name"] = json!("renamed-viewer");
    assert_eq!(
        resolve_requires((&manifest, cid.as_str()), &installed)
            .unwrap_err()
            .code(),
        "core_mismatch"
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_bundle_refuses_a_viewer_named_only_by_name() {
    let world = World::new();
    let source = world.content();
    std::fs::remove_file(source.join("README.md")).unwrap();
    let base = manifest_of(&source);
    let installed = [Installed {
        name: "image-viewer".into(),
        version: "0.1.0".into(),
        cid: base["viewer"]["cid"].as_str().unwrap().into(),
    }];
    for (index, viewer) in [
        json!("image-viewer"),
        json!({"name": "image-viewer"}),
        Value::Null,
    ]
    .into_iter()
    .enumerate()
    {
        let mut manifest = base.clone();
        manifest["viewer"] = viewer;
        write_manifest(&source, &manifest);
        let cid = capsule_bundle::closure_cid(&source).unwrap().0;
        let refusal = resolve_requires((&manifest, cid.as_str()), &installed).unwrap_err();
        assert_eq!(refusal.code(), "core_unpinned");
        assert_eq!(refusal.to_string(), format!("core_unpinned: Content {cid} must pin its viewer with viewer.cid; a name alone cannot select it."));
        let into = world.path(&format!("unpinned-{index}"));
        assert_eq!(
            pack(&source, &into, &[]).unwrap_err().code(),
            "core_unpinned"
        );
        assert!(!into.exists());
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_bundle_refuses_invalid_content_bindings() {
    let world = World::new();
    let source = world.content();
    std::fs::remove_file(source.join("README.md")).unwrap();
    let base = manifest_of(&source);
    let mut cases = Vec::new();
    for (field, value) in [
        ("execution", json!("component")),
        ("permissions", json!({})),
        ("capabilities", json!([])),
        ("requires", json!([])),
    ] {
        let mut manifest = base.clone();
        manifest[field] = value;
        cases.push((
            manifest,
            format!("field {field} is outside the passive photo profile"),
        ));
    }
    let mut extra = base.clone();
    extra["viewer"]["url"] = json!("unused");
    cases.push((extra, "viewer must have only name and cid".into()));
    for (viewer, detail) in [
        (
            json!({"name": "image-viewer", "url": "unused"}),
            "viewer must have only name and cid",
        ),
        (json!(42), "viewer must be an object with only name and cid"),
        (
            json!({"cid": base["viewer"]["cid"]}),
            "viewer must have only name and cid",
        ),
        (
            json!({"name": "", "cid": base["viewer"]["cid"]}),
            "viewer.name must be a nonempty string",
        ),
        (
            json!({"name": "image-viewer", "cid": 42}),
            "viewer.cid must be a CID string",
        ),
        (
            json!({"name": "image-viewer", "cid": "../viewer"}),
            "viewer.cid must be a CID string",
        ),
    ] {
        let mut manifest = base.clone();
        manifest["viewer"] = viewer;
        cases.push((manifest, detail.into()));
    }
    let mut executable = base.clone();
    executable["type"] = json!("wasm");
    cases.push((
        executable,
        "schema, role and type must describe passive photo content".into(),
    ));
    for path in ["01.png", "other/01.png", "images/nested/01.png"] {
        let mut manifest = base.clone();
        manifest["entrypoint"] = json!(path);
        cases.push((
            manifest,
            "entrypoint must name a regular file directly in images/".into(),
        ));
    }
    for path in ["images/bad?.png", "images/bad#.png"] {
        let mut manifest = base.clone();
        manifest["entrypoint"] = json!(path);
        cases.push((
            manifest,
            format!("{path}: uri must not contain ?, #, \\ or control characters"),
        ));
    }
    for (index, (manifest, detail)) in cases.into_iter().enumerate() {
        write_manifest(&source, &manifest);
        let cid = capsule_bundle::closure_cid(&source).unwrap().0;
        binding_refusal(
            resolve_requires((&manifest, cid.as_str()), &[]).unwrap_err(),
            &cid,
            &detail,
        );
        let into = world.path(&format!("invalid-{index}"));
        binding_refusal(pack(&source, &into, &[]).unwrap_err(), "unpacked", &detail);
        assert!(!into.exists());
    }
    write_manifest(&source, &base);
    // A sibling filename is validated too, before any output exists.
    write(&source.join("images/bad?.png"), b"invalid member URI");
    let detail = "images/bad?.png: uri must not contain ?, #, \\ or control characters";
    binding_refusal(
        validate_content_stand_in(&base, "unpacked", &["images/bad?.png"]).unwrap_err(),
        "unpacked",
        detail,
    );
    let into = world.path("invalid-member");
    binding_refusal(pack(&source, &into, &[]).unwrap_err(), "unpacked", detail);
    assert!(!into.exists());
    std::fs::remove_file(source.join("images/bad?.png")).unwrap();
    let into = world.path("added-requirement");
    binding_refusal(
        pack(
            &source,
            &into,
            &[(
                "extra".into(),
                base["viewer"]["cid"].as_str().unwrap().into(),
            )],
        )
        .unwrap_err(),
        "unpacked",
        "field requires is outside the passive photo profile",
    );
    assert!(!into.exists());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_bundle_refuses_unresolved_dependencies() {
    let world = World::new();
    let (installed, surface) = world.dependencies();
    let source = world.content();
    let mut content = manifest_of(&source);
    content["viewer"]["cid"] = json!(installed[3].cid);
    for (manifest, selected, other) in [
        (&content, &installed[3], &installed[1]),
        (&surface, &installed[2], &installed[0]),
    ] {
        // A real but unrelated installed selection cannot supply this edge.
        let unrelated = Installed {
            name: "unrelated".into(),
            cid: capsule_bundle::cid_v1_raw_sha256(b"unrelated"),
            version: "0.1.0".into(),
        };
        for have in [vec![], vec![unrelated]] {
            let refusal = resolve_requires(manifest, &have).unwrap_err();
            assert_eq!(refusal.code(), "core_missing");
            assert_eq!(
                refusal.to_string(),
                format!(
                    "core_missing: Required {} at {} is absent; admit that exact dependency.",
                    selected.name, selected.cid
                )
            );
        }
        let refusal = resolve_requires(manifest, std::slice::from_ref(other)).unwrap_err();
        assert_eq!(refusal.code(), "core_mismatch");
        assert_eq!(
            refusal.to_string(),
            format!(
                "core_mismatch: Required {} at {} differs from installed {} {}.",
                selected.name, selected.cid, other.name, other.cid
            )
        );
    }
}
