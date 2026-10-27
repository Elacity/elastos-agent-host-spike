//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use capsule_bundle::{
    effective_policy, load, pack, sign, testing::unseal, Claim, Installed, Loaded, LocalConfig,
    PolicyFloor, PublisherEntry, ReleasePolicy, SignedClaim, TrustPolicy,
};
use serde_json::{json, Value};

#[path = "support/ph6_stand_in.rs"]
mod stand_in;
use stand_in::{open_content_stand_in, StandInEvidence, StandInLaunchError, ALBUM};

const NOW: u64 = 1_800_000_000;
const IMAGES: [(&str, &str); 3] = [
    ("images/01.png", "image/png"),
    ("images/02.jpg", "image/jpeg"),
    ("images/03.webp", "image/webp"),
];

struct TempRoot {
    _temp: tempfile::TempDir,
    path: PathBuf,
}

impl TempRoot {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        Self { _temp: temp, path }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        unseal(&self.path);
    }
}

struct Fixture {
    _root: TempRoot,
    store: PathBuf,
    source_core: PathBuf,
    content: Loaded,
    viewer: Loaded,
    core: Loaded,
    installed: Vec<Installed>,
    claims: BTreeMap<String, SignedClaim>,
    policy: TrustPolicy,
}

impl Fixture {
    fn new(images: &[(&str, Vec<u8>)]) -> Self {
        let root = TempRoot::new();
        let store = root.path.join("store");
        std::fs::create_dir(&store).unwrap();
        let source_core = root.path.join("core-source");
        std::fs::create_dir(&source_core).unwrap();
        for name in ["capsule.json", "photo-viewer.component.wasm"] {
            std::fs::copy(photo_dir().join(name), source_core.join(name)).unwrap();
        }
        let core = stage(&root.path, &store, &source_core, &[]);
        let viewer = stage(
            &root.path,
            &store,
            &photo_dir().join("surface"),
            &[("photo-viewer".into(), core.cid.clone())],
        );
        let source_content = root.path.join("content-source");
        std::fs::create_dir_all(source_content.join("images")).unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(fixture_dir().join("capsule.json")).unwrap())
                .unwrap();
        manifest["viewer"]["cid"] = json!(viewer.cid);
        std::fs::write(
            source_content.join("capsule.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        for (name, bytes) in images {
            std::fs::write(source_content.join(name), bytes).unwrap();
        }
        let content = stage(&root.path, &store, &source_content, &[]);

        // Disposable fixture signing material stays in memory.
        let publisher = sign::generate();
        let mut installed = Vec::new();
        let mut claims = BTreeMap::new();
        for package in [&core, &viewer, &content] {
            let name = package.manifest["name"].as_str().unwrap().to_string();
            let version = package.manifest["version"].as_str().unwrap().to_string();
            installed.push(Installed {
                name: name.clone(),
                version: version.clone(),
                cid: package.cid.clone(),
            });
            let claim = Claim {
                cid: package.cid.clone(),
                name,
                version,
                role: package.manifest["role"].as_str().unwrap().into(),
                publisher_did: sign::did(&publisher),
            }
            .sign(&publisher);
            claims.insert(package.cid.clone(), claim);
        }
        let release_root = sign::generate();
        let release = ReleasePolicy {
            sequence: 1,
            expires_at: NOW + 3600,
            publishers: vec![PublisherEntry {
                did: sign::did(&publisher),
                roles: vec!["app".into(), "viewer".into(), "content".into()],
                names: None,
            }],
            revoked_dids: vec![],
            revoked_cids: vec![],
        };
        let policy = effective_policy(
            &release.sign(&release_root),
            &sign::did(&release_root),
            &LocalConfig::default(),
            NOW,
            &PolicyFloor::at(root.path.join("floor")),
        )
        .unwrap();
        Self {
            _root: root,
            store,
            source_core,
            content,
            viewer,
            core,
            installed,
            claims,
            policy,
        }
    }

    fn uri(&self, path: &str) -> String {
        format!(
            "localhost://Users/self/Pictures/Capsules/{}/{path}",
            self.content.cid
        )
    }

    fn item(&self, order: usize, path: &str, mime: &str) -> Value {
        json!({
            "order": order, "uri": self.uri(path), "mime": mime,
            "width": 4, "height": 4, "duration_ms": 5000,
        })
    }
}

fn photo_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .canonicalize()
        .unwrap()
}

fn fixture_dir() -> PathBuf {
    photo_dir().join("host-test/fixtures/stand-in-photo-set")
}

fn fixture_images() -> Vec<(&'static str, Vec<u8>)> {
    IMAGES
        .iter()
        .map(|(path, _)| (*path, std::fs::read(fixture_dir().join(path)).unwrap()))
        .collect()
}

fn stage(root: &Path, store: &Path, source: &Path, requires: &[(String, String)]) -> Loaded {
    let packed = root.join("packed");
    let (cid, _) = pack(source, &packed, requires).unwrap();
    let staged = store.join(&cid);
    std::fs::rename(packed, &staged).unwrap();
    seal(&staged);
    load(store, &cid).unwrap()
}

fn seal(path: &Path) {
    let mode = if path.is_dir() {
        for entry in std::fs::read_dir(path).unwrap() {
            seal(&entry.unwrap().path());
        }
        0o555
    } else {
        0o444
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn checked_playlist(fixture: &Fixture, evidence: &StandInEvidence) {
    assert_eq!(
        evidence.playlist["schema"],
        "elastos.photo-viewer.playlist/v1"
    );
    assert_eq!(evidence.playlist["album"], ALBUM);
    assert_eq!(evidence.playlist["skipped"], json!([]));
    let items: Vec<_> = IMAGES
        .iter()
        .enumerate()
        .map(|(order, (path, mime))| fixture.item(order, path, mime))
        .collect();
    assert_eq!(evidence.playlist["items"], json!(items));
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stand_in_opens_content_cid_and_writes_checked_playlist() {
    let images = fixture_images();
    let fixture = Fixture::new(&images);
    let evidence = open_content_stand_in(
        &fixture.store,
        &fixture.content.cid,
        &fixture.viewer.cid,
        &fixture.core.cid,
        &fixture.claims,
        &fixture.policy,
        &fixture.installed,
        NOW,
        &fixture.source_core,
        None,
    )
    .await
    .expect("the admitted core writes a checked playlist");
    assert_eq!(evidence.content_cid, fixture.content.cid);
    assert_eq!(evidence.viewer_cid, fixture.viewer.cid);
    assert_eq!(evidence.core_cid, fixture.core.cid);
    checked_playlist(&fixture, &evidence);
    for (path, bytes) in images {
        let uri = fixture.uri(path);
        assert!(evidence.bytes_served[&uri] > 0);
        assert!(evidence.bytes_served[&uri] < bytes.len());
        assert!(evidence.lines.iter().any(|line| {
            let request = &line["request"];
            request["type"] == "resource_invoke"
                && request["uri"] == uri
                && request["operation"] == "read"
                && request["body"]["offset"] == 0
                && request["body"]["length"] == 32
        }));
    }
    assert!(!fixture.source_core.exists());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stand_in_runs_the_staged_core() {
    let fixture = Fixture::new(&fixture_images());
    let evidence = open_content_stand_in(
        &fixture.store,
        &fixture.content.cid,
        &fixture.viewer.cid,
        &fixture.core.cid,
        &fixture.claims,
        &fixture.policy,
        &fixture.installed,
        NOW,
        &fixture.source_core,
        None,
    )
    .await
    .expect("the staged core runs after its source is removed");
    checked_playlist(&fixture, &evidence);
    assert!(!fixture.source_core.exists());
    assert!(fixture
        .core
        .path
        .join("photo-viewer.component.wasm")
        .is_file());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stand_in_preserves_content_skip_and_authority_stop() {
    let mut images = fixture_images();
    images.truncate(1);
    images.push(("images/note.png", b"GIF89a....".to_vec()));
    let fixture = Fixture::new(&images);
    let evidence = open_content_stand_in(
        &fixture.store,
        &fixture.content.cid,
        &fixture.viewer.cid,
        &fixture.core.cid,
        &fixture.claims,
        &fixture.policy,
        &fixture.installed,
        NOW,
        &fixture.source_core,
        None,
    )
    .await
    .expect("the core skips bad content");
    assert_eq!(
        evidence.playlist["items"],
        json!([fixture.item(0, "images/01.png", "image/png")])
    );
    let skipped = evidence.playlist["skipped"].as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["order"], 1);
    assert_eq!(skipped[0]["reason"], "wrong_type");
    let note_uri = fixture.uri("images/note.png");
    assert_eq!(skipped[0]["uri"], note_uri);
    // A successful read proves the bridge kept the note in its granted read set.
    assert_eq!(evidence.bytes_served[&note_uri], b"GIF89a....".len());
    assert!(evidence.lines.iter().any(|line| {
        let request = &line["request"];
        request["type"] == "resource_invoke"
            && request["uri"] == note_uri
            && request["operation"] == "read"
    }));

    let fixture = Fixture::new(&fixture_images());
    let denied_uri = fixture.uri("images/01.png");
    let error = open_content_stand_in(
        &fixture.store,
        &fixture.content.cid,
        &fixture.viewer.cid,
        &fixture.core.cid,
        &fixture.claims,
        &fixture.policy,
        &fixture.installed,
        NOW,
        &fixture.source_core,
        Some(&denied_uri),
    )
    .await
    .expect_err("a missing read grant stops the core");
    let StandInLaunchError::Launch {
        stage,
        reason,
        wrote_playlist,
    } = error
    else {
        panic!("expected a launch failure, got {error}");
    };
    assert_eq!(stage, "run");
    assert!(!wrote_playlist);
    assert!(reason.contains("Denied"), "{reason}");
    assert!(reason.contains(&denied_uri), "{reason}");
}
