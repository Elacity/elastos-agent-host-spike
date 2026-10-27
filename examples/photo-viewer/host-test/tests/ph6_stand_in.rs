//! This test code stands in for the Runtime's launch by CID, which does not exist yet.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use capsule_bundle::{
    effective_policy, load, pack, sign, testing::unseal, Claim, Installed, Loaded, LocalConfig,
    PolicyFloor, PublisherEntry, Refusal, ReleasePolicy, SignedClaim, SignedReleasePolicy,
    TrustPolicy,
};
use capsule_v1_host_test::{dispatch, Bridge, STAND_IN_TEST_PRINCIPAL};
use serde_json::{json, Value};

#[path = "support/ph6_stand_in.rs"]
mod stand_in;
use stand_in::{
    arm_content_stand_in, close_content_stand_in, content_readmit, launch_members,
    open_content_stand_in, StandInEvidence, StandInLaunchError, ALBUM, PLAYLIST,
};

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
    release: ReleasePolicy,
    sign_release: Box<dyn Fn(&ReleasePolicy) -> SignedReleasePolicy>,
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
            &release.clone().sign(&release_root),
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
            release,
            sign_release: Box::new(move |policy| policy.clone().sign(&release_root)),
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
    assert!(evidence.armed);
    assert!(!evidence.binding_active);
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
    assert!(evidence.armed);
    assert!(!evidence.binding_active);
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
    assert!(evidence.armed);
    assert!(!evidence.binding_active);
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

const CONTENT: &str = "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku";
const INSTANCE: &str = "stand-in-instance";
const CLOSED: &str = "This stand-in launch is closed or belongs to another instance/principal.";

fn member() -> String {
    format!("localhost://Users/self/Pictures/Capsules/{CONTENT}/images/01.png")
}

fn photo_bridge() -> (Bridge, BTreeMap<String, Vec<u8>>) {
    let images = BTreeMap::from([(member(), b"image bytes".to_vec())]);
    let objects: Vec<_> = images.clone().into_iter().collect();
    (
        Bridge::with_list(ALBUM, "elastos.photo-viewer.album/v1", PLAYLIST, &objects),
        images,
    )
}

fn arm(bridge: &mut Bridge, id: &str, images: &BTreeMap<String, Vec<u8>>) {
    arm_content_stand_in(
        bridge,
        id.into(),
        CONTENT.into(),
        launch_members(ALBUM, PLAYLIST, images),
        Box::new(|| Ok(())),
    );
    // Dispatch-only tests supply the caller that run records after loading.
    if let Some(binding) = bridge.stand_in.as_mut() {
        binding.instance_id = INSTANCE.into();
    }
}

fn grant(bridge: &mut Bridge, uri: &str, action: &str, instance: &str) -> String {
    let line = json!({ "id": 1, "request": {
        "type": "request_capability", "resource": uri, "action": action,
    } });
    let response = dispatch(bridge, &line.to_string(), instance, STAND_IN_TEST_PRINCIPAL);
    assert_eq!(
        response["response"]["type"], "capability_token",
        "{response}"
    );
    response["response"]["token"].as_str().unwrap().into()
}

fn read(uri: &str, token: &str) -> String {
    json!({ "id": 2, "request": {
        "type": "resource_invoke", "uri": uri, "operation": "read", "token": token,
        "body": { "path": uri, "offset": 0, "length": 32 },
    } })
    .to_string()
}

fn write_playlist(token: &str) -> String {
    json!({ "id": 2, "request": {
        "type": "resource_invoke", "uri": PLAYLIST, "operation": "write", "token": token,
        "body": { "path": PLAYLIST, "content": b"{}".to_vec(), "append": false },
    } })
    .to_string()
}

fn assert_refused(response: Value, code: &str, message: &str) {
    assert_eq!(
        response,
        json!({ "id": 2, "response": {
        "type": "error", "code": code, "message": message,
    } })
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_denies_a_read_outside_bound_content() {
    let (mut bridge, images) = photo_bridge();
    assert_eq!(
        launch_members(ALBUM, PLAYLIST, &images),
        [ALBUM.into(), PLAYLIST.into(), member()].into()
    );
    let other_cid = capsule_bundle::cid_v1_raw_sha256(b"another content capsule");
    let outside = [
        format!("localhost://Users/self/Pictures/Capsules/{CONTENT}/images/other.png"),
        format!("localhost://Users/self/Pictures/Capsules/{other_cid}/images/other.png"),
        "localhost://Users/self/Pictures/other.png".into(),
        format!("localhost://Users/self/Pictures/Capsules/{CONTENT}/images/../secret.png"),
    ];
    let mut reads = Vec::new();
    for uri in &outside {
        bridge.put(uri, b"outside bytes".to_vec());
        bridge.allow(uri, "read");
        // Valid ordinary grants ensure downstream absence cannot mask a missing guard.
        let token = grant(&mut bridge, uri, "read", INSTANCE);
        reads.push(read(uri, &token));
    }
    bridge.lines.clear();
    arm(&mut bridge, "stand-in-outside", &images);
    for (uri, line) in outside.iter().zip(reads) {
        assert_refused(
            dispatch(&mut bridge, &line, INSTANCE, STAND_IN_TEST_PRINCIPAL),
            "denied",
            &format!("Read {uri} is outside content {CONTENT} bound to this stand-in launch."),
        );
        assert_eq!(bridge.bytes_served.values().sum::<usize>(), 0);
        assert!(bridge.lines.is_empty());
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stand_in_refuses_revoked_content_at_open() {
    let fixture = Fixture::new(&fixture_images());
    let mut policy = fixture.policy.clone();
    policy.revoked_cids.push(fixture.content.cid.clone());
    let error = open_content_stand_in(
        &fixture.store,
        &fixture.content.cid,
        &fixture.viewer.cid,
        &fixture.core.cid,
        &fixture.claims,
        &policy,
        &fixture.installed,
        NOW,
        &fixture.source_core,
        None,
    )
    .await
    .expect_err("revoked content is refused before running");
    assert!(
        matches!(error, StandInLaunchError::Bundle(Refusal::CidRevoked(cid))
        if cid == fixture.content.cid)
    );
    assert!(fixture.source_core.exists());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_stops_when_content_is_revoked_after_grant() {
    let fixture = Fixture::new(&fixture_images());
    let policy = Arc::new(Mutex::new(fixture.policy.clone()));
    let images = capsule_bundle::bind_content_stand_in(&fixture.content).unwrap();
    let objects: Vec<_> = images.clone().into_iter().collect();
    let mut bridge = Bridge::with_list(ALBUM, "elastos.photo-viewer.album/v1", PLAYLIST, &objects);
    arm_content_stand_in(
        &mut bridge,
        format!("stand-in-{}", fixture.content.cid),
        fixture.content.cid.clone(),
        launch_members(ALBUM, PLAYLIST, &images),
        content_readmit(
            [
                fixture.content.clone(),
                fixture.viewer.clone(),
                fixture.core.clone(),
            ],
            fixture.claims.clone(),
            Arc::clone(&policy),
            fixture.installed.clone(),
            fixture.store.clone(),
            NOW,
        ),
    );
    let uri = fixture.uri("images/01.png");
    let token = grant(&mut bridge, &uri, "read", "");
    assert!(token.starts_with(&format!("stand-in-{}/", fixture.content.cid)));
    let output_token = grant(&mut bridge, PLAYLIST, "write", "");
    policy
        .lock()
        .unwrap()
        .revoked_cids
        .push(fixture.content.cid.clone());
    let reason = format!(
        "Content CID {} is revoked by the current policy; this launch is stopped.",
        fixture.content.cid
    );
    for line in [read(&uri, &token), write_playlist(&output_token)] {
        assert_refused(
            dispatch(&mut bridge, &line, "", STAND_IN_TEST_PRINCIPAL),
            "denied",
            &reason,
        );
        assert_eq!(bridge.bytes_served.values().sum::<usize>(), 0);
        assert!(!bridge.written.contains_key(PLAYLIST));
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stand_in_refuses_a_policy_held_before_revocation() {
    let fixture = Fixture::new(&fixture_images());
    let mut release = fixture.release.clone();
    release.sequence = 2;
    release.revoked_cids.push(fixture.content.cid.clone());
    let signed = (fixture.sign_release)(&release);
    let current = effective_policy(
        &signed,
        &signed.signer_did,
        &LocalConfig::default(),
        NOW,
        &fixture.policy.floor,
    )
    .unwrap();
    assert_eq!(current.sequence, 2);
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
        None,
    )
    .await
    .expect_err("a held policy cannot outlive its accepted floor");
    assert!(matches!(
        error,
        StandInLaunchError::Bundle(Refusal::PolicyStale {
            sequence: 1,
            seen: Some(2)
        })
    ));
    assert!(fixture.source_core.exists());
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_denies_closed_or_foreign_launches() {
    for (close, principal, instance) in [
        (true, STAND_IN_TEST_PRINCIPAL, INSTANCE),
        (false, "person:other", INSTANCE),
        (false, "", INSTANCE),
        (false, STAND_IN_TEST_PRINCIPAL, "other-instance"),
    ] {
        let (mut bridge, images) = photo_bridge();
        arm(&mut bridge, "stand-in-caller", &images);
        let token = grant(&mut bridge, &member(), "read", INSTANCE);
        if close {
            close_content_stand_in(&mut bridge);
        }
        assert_refused(
            dispatch(&mut bridge, &read(&member(), &token), instance, principal),
            "denied",
            CLOSED,
        );
        assert_eq!(bridge.bytes_served.values().sum::<usize>(), 0);
    }
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_grants_are_specific_to_one_run() {
    let (mut first, images) = photo_bridge();
    let (mut second, _) = photo_bridge();
    arm(&mut first, "stand-in-a", &images);
    arm(&mut second, "stand-in-b", &images);
    let first_token = grant(&mut first, &member(), "read", INSTANCE);
    let second_token = grant(&mut second, &member(), "read", INSTANCE);
    assert_refused(
        dispatch(
            &mut second,
            &read(&member(), &first_token),
            INSTANCE,
            STAND_IN_TEST_PRINCIPAL,
        ),
        "capability_denied",
        "The grant belongs to another stand-in launch.",
    );
    assert_eq!(second.bytes_served.values().sum::<usize>(), 0);
    let own = dispatch(
        &mut second,
        &read(&member(), &second_token),
        INSTANCE,
        STAND_IN_TEST_PRINCIPAL,
    );
    assert_eq!(
        own["response"]["result"]["data"]["content"],
        json!(images[&member()])
    );
}

/// This test code stands in for the Runtime's launch by CID, which does not exist yet.
#[test]
fn stand_in_rechecks_authority_on_each_invoke() {
    let (mut bridge, images) = photo_bridge();
    arm(&mut bridge, "stand-in-invoke", &images);
    let input = grant(&mut bridge, &member(), "read", INSTANCE);
    let output = grant(&mut bridge, PLAYLIST, "write", INSTANCE);
    close_content_stand_in(&mut bridge);
    for line in [read(&member(), &input), write_playlist(&output)] {
        assert_refused(
            dispatch(&mut bridge, &line, INSTANCE, STAND_IN_TEST_PRINCIPAL),
            "denied",
            CLOSED,
        );
        assert_eq!(bridge.bytes_served.values().sum::<usize>(), 0);
        assert!(!bridge.written.contains_key(PLAYLIST));
    }
}
