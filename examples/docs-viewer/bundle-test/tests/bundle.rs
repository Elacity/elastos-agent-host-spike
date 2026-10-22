//! Pattern 3 for the documents viewer: each capsule is packed into a closure,
//! named by the CID of that closure, claimed by a publisher DID, and admitted
//! only under a policy that lets that publisher ship that role and name. The
//! surface names its core by CID.
//!
//! The bundle tool (`capsule-bundle`) is used as it is. What it does not have,
//! a step that decides which files ship, is `pack` here.
//!
//! Build the core first: `../build.sh`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use capsule_bundle::sign;
use capsule_bundle::*;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

/// Unix seconds; every test runs at this time (as in the bundle tool's tests).
const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 3600;

fn viewer_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn manifest_of(dir: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(dir.join("capsule.json")).unwrap()).unwrap()
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::copy(from, to).unwrap_or_else(|err| panic!("{}: {err}", from.display()));
}

/// The files a capsule ships: its manifest, and its entrypoint, or for a page
/// every file in the entrypoint's folder. Source, tests, fixtures and build
/// output stay behind. `requires` is set on the shipped manifest.
fn pack(source: &Path, into: &Path, requires: Option<Value>) -> PathBuf {
    let mut manifest = manifest_of(source);
    let entrypoint = manifest["entrypoint"].as_str().unwrap().to_string();
    std::fs::create_dir_all(into).unwrap();
    if manifest["execution"] == "web-projection" {
        let folder = Path::new(&entrypoint).parent().unwrap();
        let mut files: Vec<_> = std::fs::read_dir(source.join(folder))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        files.sort();
        for file in files {
            assert!(file.is_file(), "{} is not a file", file.display());
            copy(&file, &into.join(folder).join(file.file_name().unwrap()));
        }
    } else {
        let artifact = source.join(&entrypoint);
        assert!(
            artifact.is_file(),
            "{} is missing; run examples/docs-viewer/build.sh first",
            artifact.display()
        );
        copy(&artifact, &into.join(&entrypoint));
    }
    if let Some(requires) = requires {
        manifest["requires"] = requires;
    }
    std::fs::write(
        into.join("capsule.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    into.to_path_buf()
}

struct World {
    root: tempfile::TempDir,
    release_root: SigningKey,
    publisher: SigningKey,
}

impl World {
    fn new() -> World {
        World {
            root: tempfile::tempdir().unwrap(),
            release_root: sign::generate(),
            publisher: sign::generate(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn store(&self) -> PathBuf {
        self.path("store")
    }

    fn core(&self) -> PathBuf {
        pack(&viewer_dir(), &self.path("core"), None)
    }

    fn surface(&self, core_cid: Option<&str>) -> PathBuf {
        let mut requirement = json!({ "name": "docs-viewer", "kind": "capsule" });
        if let Some(cid) = core_cid {
            requirement["cid"] = json!(cid);
        }
        pack(
            &viewer_dir().join("surface"),
            &self.path(&format!("surface-{}", core_cid.unwrap_or("unpinned"))),
            Some(json!([requirement])),
        )
    }

    /// A policy from the pinned release root that lets `publisher` ship
    /// `entries`, on a new device.
    fn policy(&self, entries: Vec<PublisherEntry>) -> TrustPolicy {
        let release = ReleasePolicy {
            sequence: 1,
            expires_at: NOW + DAY,
            publishers: entries,
            revoked_dids: vec![],
            revoked_cids: vec![],
        };
        effective_policy(
            &release.sign(&self.release_root),
            &sign::did(&self.release_root),
            &LocalConfig::default(),
            NOW,
            &PolicyFloor::at(self.path(&format!("floor-{}", rand_name()))),
        )
        .unwrap()
    }

    /// The publisher may ship the core and the surface, as an app and a
    /// viewer, by name. One entry: the tool reads only the first entry for a
    /// DID (`the_second_entry_for_a_publisher_is_ignored`).
    fn docs_policy(&self) -> TrustPolicy {
        self.policy(vec![PublisherEntry {
            did: sign::did(&self.publisher),
            roles: vec!["app".into(), "viewer".into()],
            names: Some(vec!["docs-viewer".into(), "docs-reader".into()]),
        }])
    }

    fn claim(&self, key: &SigningKey, dir: &Path, role: &str) -> SignedClaim {
        let manifest = manifest_of(dir);
        let (cid, _) = closure_cid(dir).unwrap();
        Claim {
            cid,
            name: manifest["name"].as_str().unwrap().into(),
            version: manifest["version"].as_str().unwrap().into(),
            role: role.into(),
            publisher_did: sign::did(key),
        }
        .sign(key)
    }

    fn admit(
        &self,
        dir: &Path,
        claim: &SignedClaim,
        policy: &TrustPolicy,
    ) -> Result<Admitted, Refusal> {
        admit(dir, claim, policy, &[], &self.store(), NOW)
    }
}

impl Drop for World {
    /// The store is sealed read-only; open it again so the temp dir goes.
    fn drop(&mut self) {
        unseal(self.root.path());
    }
}

fn unseal(path: &Path) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        for child in std::fs::read_dir(path).unwrap() {
            unseal(&child.unwrap().path());
        }
    } else if meta.is_file() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}

fn rand_name() -> String {
    hex(&sign::generate().to_bytes()[..6])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn refused<T: std::fmt::Debug>(result: Result<T, Refusal>) -> &'static str {
    let refusal = result.expect_err("expected a refusal");
    println!("refused: {refusal}");
    refusal.code()
}

fn installed(admitted: &Admitted) -> Installed {
    Installed {
        name: admitted.name.clone(),
        version: admitted.version.clone(),
        cid: admitted.cid.clone(),
    }
}

#[test]
fn each_capsule_ships_only_what_it_runs_from() {
    let world = World::new();
    let core = world.core();
    let names = |dir: &Path| -> Vec<String> {
        list_closure(dir)
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect()
    };
    assert_eq!(names(&core), ["capsule.json", "docs-viewer.component.wasm"]);
    let surface = world.surface(Some(&closure_cid(&core).unwrap().0));
    assert_eq!(
        names(&surface),
        [
            "browser/index.html",
            "browser/main.js",
            "browser/reader.css",
            "browser/reader.js",
            "capsule.json",
        ]
    );
    // The source folders are not closures: they hold source, tests, fixtures
    // and build output, so their CID would change with anything in them.
    let source = list_closure(&viewer_dir().join("surface")).unwrap();
    assert!(source
        .iter()
        .any(|entry| entry.path == "fixtures/pages.json"));
}

#[test]
fn the_core_is_named_by_its_closure_cid_and_admitted_for_its_publisher_and_role() {
    let world = World::new();
    let core = world.core();
    let (cid, _) = closure_cid(&core).unwrap();
    println!("docs-viewer closure CID: {cid}");
    assert!(cid.starts_with("bafkrei"), "{cid}");
    let admitted = world
        .admit(
            &core,
            &world.claim(&world.publisher, &core, "app"),
            &world.docs_policy(),
        )
        .unwrap();
    assert_eq!(admitted.cid, cid);
    assert_eq!(admitted.role, "app");
    assert_eq!(admitted.name, "docs-viewer");
    // It runs only from its read-only copy under its CID.
    let loaded = load(&world.store(), &cid).unwrap();
    assert_eq!(loaded.path, world.store().join(&cid));
    assert_eq!(loaded.manifest["entrypoint"], "docs-viewer.component.wasm");
}

#[test]
fn the_surface_names_its_core_by_cid_and_nothing_else_selects_it() {
    let world = World::new();
    let policy = world.docs_policy();
    let core = world.core();
    let core = world
        .admit(&core, &world.claim(&world.publisher, &core, "app"), &policy)
        .unwrap();
    let have = [installed(&core)];

    let surface = world.surface(Some(&core.cid));
    let admitted = world
        .admit(
            &surface,
            &world.claim(&world.publisher, &surface, "viewer"),
            &policy,
        )
        .unwrap();
    println!("docs-reader closure CID: {}", admitted.cid);
    let loaded = load(&world.store(), &admitted.cid).unwrap();
    assert_eq!(resolve_requires(&loaded.manifest, &have).unwrap(), have);

    // By name alone, or naming another build of the core: refused.
    let unpinned = world.surface(None);
    assert_eq!(
        refused(resolve_requires(&manifest_of(&unpinned), &have)),
        "core_unpinned"
    );
    let other = world.surface(Some(
        "bafkreiaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ));
    assert_eq!(
        refused(resolve_requires(&manifest_of(&other), &have)),
        "core_mismatch"
    );
    // The surface's own CID changes with the core it names.
    assert_ne!(closure_cid(&other).unwrap().0, admitted.cid);
}

#[test]
fn the_publisher_ships_only_the_role_and_name_the_policy_gives_it() {
    let world = World::new();
    let core = world.core();
    let surface = world.surface(Some(&closure_cid(&core).unwrap().0));

    // Viewer only, by name: the core (an app) is refused, the surface is not.
    let viewer_only = world.policy(vec![PublisherEntry {
        did: sign::did(&world.publisher),
        roles: vec!["viewer".into()],
        names: Some(vec!["docs-reader".into()]),
    }]);
    assert_eq!(
        refused(world.admit(
            &core,
            &world.claim(&world.publisher, &core, "app"),
            &viewer_only
        )),
        "publisher_role_refused"
    );
    world
        .admit(
            &surface,
            &world.claim(&world.publisher, &surface, "viewer"),
            &viewer_only,
        )
        .unwrap();

    // The photo viewer's names do not cover the documents viewer.
    let photos = world.policy(vec![PublisherEntry {
        did: sign::did(&world.publisher),
        roles: vec!["app".into(), "viewer".into()],
        names: Some(vec!["photo-viewer".into(), "image-viewer".into()]),
    }]);
    assert_eq!(
        refused(world.admit(&core, &world.claim(&world.publisher, &core, "app"), &photos)),
        "publisher_role_refused"
    );

    // Another publisher, and a claim for another role than the manifest's.
    let stranger = sign::generate();
    assert_eq!(
        refused(world.admit(
            &core,
            &world.claim(&stranger, &core, "app"),
            &world.docs_policy()
        )),
        "publisher_untrusted"
    );
    assert_eq!(
        refused(world.admit(
            &core,
            &world.claim(&world.publisher, &core, "viewer"),
            &world.docs_policy()
        )),
        "claim_manifest_mismatch"
    );
}

#[test]
fn a_changed_closure_is_not_the_claimed_one() {
    let world = World::new();
    let core = world.core();
    let claim = world.claim(&world.publisher, &core, "app");
    // One byte of the component changed after the claim.
    let wasm = core.join("docs-viewer.component.wasm");
    let mut bytes = std::fs::read(&wasm).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&wasm, bytes).unwrap();
    assert_eq!(
        refused(world.admit(&core, &claim, &world.docs_policy())),
        "cid_mismatch"
    );
    // The source folder is not the packed closure, so the claim does not fit it.
    let world = World::new();
    let core = world.core();
    let claim = world.claim(&world.publisher, &core, "app");
    let surface_source = viewer_dir().join("surface");
    assert_eq!(
        refused(world.admit(&surface_source, &claim, &world.docs_policy())),
        "cid_mismatch"
    );
}

#[test]
fn the_runtime_manifest_type_takes_the_core_but_not_a_core_named_by_cid() {
    let world = World::new();
    let core = world.core();
    let core_manifest: elastos_common::CapsuleManifest =
        serde_json::from_value(manifest_of(&core)).unwrap();
    core_manifest.validate().unwrap();

    // The surface as shipped here names its core by CID. Today's Runtime
    // manifest refuses that field: `requires` entries are `{name, kind}` with
    // unknown fields refused (P4 design, section 1.4).
    let surface = world.surface(Some(&closure_cid(&core).unwrap().0));
    let parsed = serde_json::from_value::<elastos_common::CapsuleManifest>(manifest_of(&surface));
    let err = parsed
        .expect_err("Runtime takes requires[].cid today?")
        .to_string();
    println!("Runtime manifest: {err}");
    assert!(err.contains("cid"), "{err}");
    // Without the CID it parses: the page itself is a valid viewer manifest.
    let unpinned = world.surface(None);
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_value(manifest_of(&unpinned)).unwrap();
    manifest.validate().unwrap();
}

/// A finding, pinned: a policy may list a publisher twice, and only the first
/// entry counts. The second grants nothing and is not refused either.
#[test]
fn the_second_entry_for_a_publisher_is_ignored() {
    let world = World::new();
    let core = world.core();
    let surface = world.surface(Some(&closure_cid(&core).unwrap().0));
    let split = world.policy(vec![
        PublisherEntry {
            did: sign::did(&world.publisher),
            roles: vec!["app".into()],
            names: Some(vec!["docs-viewer".into()]),
        },
        PublisherEntry {
            did: sign::did(&world.publisher),
            roles: vec!["viewer".into()],
            names: Some(vec!["docs-reader".into()]),
        },
    ]);
    world
        .admit(&core, &world.claim(&world.publisher, &core, "app"), &split)
        .unwrap();
    assert_eq!(
        refused(world.admit(
            &surface,
            &world.claim(&world.publisher, &surface, "viewer"),
            &split
        )),
        "publisher_role_refused"
    );
}
