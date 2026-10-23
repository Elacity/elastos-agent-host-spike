//! Every refusal of the P4b bundle tool, and the path that admits.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use capsule_bundle::sign;
use capsule_bundle::testing::{refused, unseal};
use capsule_bundle::*;
use ed25519_dalek::SigningKey;

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

/// Unix seconds; every test runs at this time.
const NOW: u64 = 1_800_000_000;
const HOUR: u64 = 3600;

struct World {
    root: Temp,
    floors: std::cell::Cell<u32>,
    release_root: SigningKey,
    publisher: SigningKey,
}

impl World {
    fn new() -> World {
        World {
            root: tempdir(),
            floors: std::cell::Cell::new(0),
            release_root: sign::generate(),
            publisher: sign::generate(),
        }
    }

    fn dir(&self, name: &str) -> PathBuf {
        let dir = self.root.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn store(&self) -> PathBuf {
        self.root.path().join("store")
    }

    /// A small photo-viewer closure at `name`.
    fn capsule(&self, name: &str, version: &str) -> PathBuf {
        let dir = self.dir(name);
        write_manifest(&dir, "photo-viewer", version, "app", None);
        std::fs::write(
            dir.join("photo-viewer.component.wasm"),
            format!("\0asm guest {version}"),
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("icons")).unwrap();
        std::fs::write(dir.join("icons/photos.png"), b"\x89PNG icon").unwrap();
        dir
    }

    /// A new device's policy floor: nothing accepted yet.
    fn floor(&self) -> PolicyFloor {
        self.floors.set(self.floors.get() + 1);
        PolicyFloor::at(
            self.root
                .path()
                .join(format!("floor-{}", self.floors.get())),
        )
    }

    fn release(&self) -> ReleasePolicy {
        ReleasePolicy {
            sequence: 1,
            expires_at: NOW + HOUR,
            publishers: vec![PublisherEntry {
                did: sign::did(&self.publisher),
                roles: vec!["app".into()],
                names: None,
            }],
            revoked_dids: vec![],
            revoked_cids: vec![],
        }
    }

    fn policy_from(&self, release: ReleasePolicy) -> TrustPolicy {
        let signed = release.sign(&self.release_root);
        effective_policy(
            &signed,
            &sign::did(&self.release_root),
            &LocalConfig::default(),
            NOW,
            &self.floor(),
        )
        .unwrap()
    }

    fn policy(&self) -> TrustPolicy {
        self.policy_from(self.release())
    }

    fn claim(&self, dir: &Path, version: &str) -> SignedClaim {
        claim_by(&self.publisher, dir, "photo-viewer", version, "app")
    }
}

impl Drop for World {
    /// The store is sealed read-only; open it again so the temp dir goes.
    fn drop(&mut self) {
        unseal(self.root.path());
    }
}

fn write_manifest(
    dir: &Path,
    name: &str,
    version: &str,
    role: &str,
    requires: Option<serde_json::Value>,
) {
    let mut manifest = serde_json::json!({
        "schema": "elastos.capsule/v1",
        "name": name,
        "version": version,
        "role": role,
        "entrypoint": "photo-viewer.component.wasm",
    });
    if let Some(requires) = requires {
        manifest["requires"] = requires;
    }
    std::fs::write(
        dir.join("capsule.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

fn claim_by(key: &SigningKey, dir: &Path, name: &str, version: &str, role: &str) -> SignedClaim {
    let (cid, _) = closure_cid(dir).unwrap();
    Claim {
        cid,
        name: name.into(),
        version: version.into(),
        role: role.into(),
        publisher_did: sign::did(key),
    }
    .sign(key)
}

fn installed(name: &str, version: &str, cid: &str) -> Installed {
    Installed {
        name: name.into(),
        version: version.into(),
        cid: cid.into(),
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777
}

// ---- The closure listing and its CID ----

#[test]
fn the_listing_is_canonical_and_names_every_shipped_file() {
    let world = World::new();
    let dir = world.dir("tiny");
    std::fs::write(dir.join("capsule.json"), b"{}").unwrap();
    std::fs::create_dir(dir.join("b")).unwrap();
    std::fs::write(dir.join("b/x"), b"x").unwrap();
    std::fs::write(dir.join("a"), b"").unwrap();

    let entries = list_closure(&dir).unwrap();
    let expected = concat!(
        r#"{"files":["#,
        r#"{"path":"a","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0},"#,
        r#"{"path":"b/x","sha256":"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881","size":1},"#,
        r#"{"path":"capsule.json","sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2}"#,
        r#"],"schema":"elastos.capsule.closure/v1"}"#,
    );
    assert_eq!(
        String::from_utf8(listing_bytes(&entries)).unwrap(),
        expected
    );
    let (cid, _) = closure_cid(&dir).unwrap();
    assert_eq!(cid, cid_v1_raw_sha256(expected.as_bytes()));
    assert!(cid.starts_with("bafkrei"), "{cid}");
}

#[test]
fn the_listing_is_sorted_by_path_bytes_not_by_walk_order() {
    // "a-b" (0x2d) sorts before "a/x" (0x2f), though a walk visits "a" first.
    let world = World::new();
    let dir = world.dir("order");
    std::fs::write(dir.join("capsule.json"), b"{}").unwrap();
    std::fs::create_dir(dir.join("a")).unwrap();
    std::fs::write(dir.join("a/x"), b"x").unwrap();
    std::fs::write(dir.join("a-b"), b"").unwrap();
    let paths: Vec<_> = list_closure(&dir)
        .unwrap()
        .into_iter()
        .map(|entry| entry.path)
        .collect();
    assert_eq!(paths, ["a-b", "a/x", "capsule.json"]);
}

#[test]
fn any_change_to_the_closure_changes_the_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let (before, _) = closure_cid(&dir).unwrap();

    std::fs::write(dir.join("icons/photos.png"), b"\x89PNG other").unwrap();
    let (changed, _) = closure_cid(&dir).unwrap();
    assert_ne!(before, changed, "a changed byte");

    std::fs::write(dir.join("icons/photos.png"), b"\x89PNG icon").unwrap();
    assert_eq!(
        closure_cid(&dir).unwrap().0,
        before,
        "the same bytes, the same CID"
    );

    std::fs::write(dir.join("extra.txt"), b"").unwrap();
    assert_ne!(closure_cid(&dir).unwrap().0, before, "an unlisted file");
    std::fs::remove_file(dir.join("extra.txt")).unwrap();

    std::fs::rename(dir.join("icons/photos.png"), dir.join("icons/photo.png")).unwrap();
    assert_ne!(closure_cid(&dir).unwrap().0, before, "a renamed file");
}

#[test]
fn the_listing_refuses_a_closure_with_no_manifest() {
    let world = World::new();
    let dir = world.dir("bare");
    std::fs::write(dir.join("photo-viewer.component.wasm"), b"\0asm").unwrap();
    assert_eq!(refused(list_closure(&dir)), "manifest_missing");
    // Only at the root.
    std::fs::create_dir(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/capsule.json"), b"{}").unwrap();
    assert_eq!(refused(list_closure(&dir)), "manifest_missing");
}

#[test]
fn the_listing_takes_ascii_or_nfc_names_only() {
    let world = World::new();
    let nfc = world.capsule("nfc", "0.1.0");
    std::fs::write(nfc.join("caf\u{e9}.png"), b"nfc").unwrap();
    std::fs::write(nfc.join("\u{65e5}\u{672c}.png"), b"nfc").unwrap();
    let entries = list_closure(&nfc).unwrap();
    assert!(entries.iter().any(|entry| entry.path == "caf\u{e9}.png"));

    // "e" then a combining acute accent: the NFD spelling of "é".
    let nfd = world.capsule("nfd", "0.1.0");
    std::fs::write(nfd.join("cafe\u{301}.png"), b"nfd").unwrap();
    assert_eq!(refused(list_closure(&nfd)), "path_not_nfc");

    // In a directory name too.
    let nfd_dir = world.capsule("nfd-dir", "0.1.0");
    std::fs::create_dir(nfd_dir.join("cafe\u{301}")).unwrap();
    std::fs::write(nfd_dir.join("cafe\u{301}/a.png"), b"nfd").unwrap();
    assert_eq!(refused(list_closure(&nfd_dir)), "path_not_nfc");
}

#[test]
fn the_listing_refuses_control_characters_and_backslashes() {
    let world = World::new();
    for name in [
        "new\nline.png",
        "tab\t.png",
        "back\\slash.png",
        "del\u{7f}.png",
    ] {
        let dir = world.capsule(&format!("bad-{}", name.len()), "0.1.0");
        std::fs::write(dir.join(name), b"x").unwrap();
        assert_eq!(refused(list_closure(&dir)), "path_invalid", "{name:?}");
        std::fs::remove_file(dir.join(name)).unwrap();
    }
}

#[test]
fn names_must_be_unique_under_case_folding() {
    for (a, b) in [
        ("A.png", "a.png"),
        ("stra\u{df}e.png", "strasse.png"),
        ("\u{3c3}.png", "\u{3c2}.png"),
    ] {
        assert_eq!(
            refused(check_unique_under_case_folding([a, b])),
            "path_case_collision",
            "{a:?} and {b:?}"
        );
    }
    assert!(check_unique_under_case_folding(["a.png", "b.png", "a/b.png"]).is_ok());

    // Through the walk, wherever the disk can hold both spellings. A
    // case-insensitive disk (the macOS APFS default) cannot hold "A" and "a",
    // nor "straße" and "strasse", and then has one file, which the walk lists
    // once: one more than the fixture had.
    let world = World::new();
    for (index, (a, b)) in [
        ("Photo.png", "photo.png"),
        ("stra\u{df}e.png", "strasse.png"),
    ]
    .into_iter()
    .enumerate()
    {
        let dir = world.capsule(&format!("case-{index}"), "0.1.0");
        let fixture = list_closure(&dir).unwrap().len();
        std::fs::write(dir.join(a), b"1").unwrap();
        let both = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(b))
            .is_ok();
        if both {
            assert_eq!(
                refused(list_closure(&dir)),
                "path_case_collision",
                "{a:?} and {b:?}"
            );
        } else {
            println!("this disk holds one of {a:?} and {b:?}");
            assert_eq!(list_closure(&dir).unwrap().len(), fixture + 1);
        }
    }
}

#[test]
fn the_listing_refuses_symlinks_and_special_files() {
    let world = World::new();

    let to_file = world.capsule("link-file", "0.1.0");
    std::os::unix::fs::symlink("photo-viewer.component.wasm", to_file.join("alias.wasm")).unwrap();
    assert_eq!(refused(list_closure(&to_file)), "special_file");

    let to_dir = world.capsule("link-dir", "0.1.0");
    std::os::unix::fs::symlink(world.dir("outside"), to_dir.join("more")).unwrap();
    assert_eq!(refused(list_closure(&to_dir)), "special_file");

    let dangling = world.capsule("link-dangling", "0.1.0");
    std::os::unix::fs::symlink("/nonexistent", dangling.join("gone")).unwrap();
    assert_eq!(refused(list_closure(&dangling)), "special_file");

    // A link in place of the manifest is not followed either.
    let manifest = world.capsule("link-manifest", "0.1.0");
    std::fs::rename(manifest.join("capsule.json"), manifest.join("real.json")).unwrap();
    std::os::unix::fs::symlink("real.json", manifest.join("capsule.json")).unwrap();
    assert_eq!(refused(list_closure(&manifest)), "special_file");

    // The root itself is not followed: a link there would list another folder.
    let real = world.capsule("link-root", "0.1.0");
    let alias = world.dir("aliases").join("link-root");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    assert_eq!(refused(list_closure(&alias)), "symlink_in_path");
    assert!(list_closure(&real).is_ok());

    let socket = world.capsule("socket", "0.1.0");
    let _listener = std::os::unix::net::UnixListener::bind(socket.join("s")).unwrap();
    assert_eq!(refused(list_closure(&socket)), "special_file");

    let fifo = world.capsule("fifo", "0.1.0");
    let made = std::process::Command::new("mkfifo")
        .arg(fifo.join("pipe"))
        .status()
        .unwrap();
    assert!(made.success());
    assert_eq!(refused(list_closure(&fifo)), "special_file");
}

// ---- The detached claim ----

#[test]
fn a_claim_parses_strictly() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    assert_eq!(SignedClaim::parse(&claim.to_bytes()).unwrap(), claim);
    claim.verify().unwrap();

    let mut extra: serde_json::Value = serde_json::from_slice(&claim.to_bytes()).unwrap();
    extra["claim"]["provenance"] = serde_json::json!({ "source_commit": "abc" });
    assert_eq!(
        refused(SignedClaim::parse(&serde_json::to_vec(&extra).unwrap())),
        "claim_malformed"
    );

    let mut schema: serde_json::Value = serde_json::from_slice(&claim.to_bytes()).unwrap();
    schema["schema"] = "elastos.capsule.claim/v2".into();
    assert_eq!(
        refused(SignedClaim::parse(&serde_json::to_vec(&schema).unwrap())),
        "claim_malformed"
    );
}

#[test]
fn admission_refuses_a_closure_that_is_not_the_claimed_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");

    std::fs::write(
        dir.join("photo-viewer.component.wasm"),
        b"\0asm other guest",
    )
    .unwrap();
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy(),
            &[],
            &world.store(),
            NOW
        )),
        "cid_mismatch"
    );

    let dir = world.capsule("source-2", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    std::fs::write(dir.join("notes.txt"), b"unlisted").unwrap();
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy(),
            &[],
            &world.store(),
            NOW
        )),
        "cid_mismatch"
    );
    assert!(!world.store().exists(), "nothing staged");
}

#[test]
fn admission_refuses_a_claim_its_publisher_did_not_sign() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let policy = world.policy();

    // Signed by another key, naming the trusted publisher.
    let mut forged = claim_by(&sign::generate(), &dir, "photo-viewer", "0.1.0", "app");
    forged.claim.publisher_did = sign::did(&world.publisher);
    assert_eq!(
        refused(admit(&dir, &forged, &policy, &[], &world.store(), NOW)),
        "signature_invalid"
    );

    // Changed after signing.
    let mut changed = world.claim(&dir, "0.1.0");
    changed.claim.role = "system".into();
    assert_eq!(
        refused(admit(&dir, &changed, &policy, &[], &world.store(), NOW)),
        "signature_invalid"
    );

    // The publisher's signature from another domain.
    let mut other_domain = world.claim(&dir, "0.1.0");
    let payload = serde_json::to_vec(&serde_json::to_value(&other_domain.claim).unwrap()).unwrap();
    other_domain.signature = sign::sign(&world.publisher, POLICY_SCHEMA, &payload).0;
    assert_eq!(
        refused(admit(
            &dir,
            &other_domain,
            &policy,
            &[],
            &world.store(),
            NOW
        )),
        "signature_invalid"
    );

    // Not hex, not 64 bytes, not a did:key.
    let mut garbage = world.claim(&dir, "0.1.0");
    garbage.signature = "zz".into();
    assert_eq!(
        refused(admit(&dir, &garbage, &policy, &[], &world.store(), NOW)),
        "signature_invalid"
    );
    let mut short = world.claim(&dir, "0.1.0");
    short.signature = "00".repeat(63);
    assert_eq!(
        refused(admit(&dir, &short, &policy, &[], &world.store(), NOW)),
        "signature_invalid"
    );
    let mut not_did = world.claim(&dir, "0.1.0");
    not_did.claim.publisher_did = "did:web:example.com".into();
    assert_eq!(
        refused(admit(&dir, &not_did, &policy, &[], &world.store(), NOW)),
        "signature_invalid"
    );
}

#[test]
fn admission_refuses_a_claim_that_is_not_what_the_manifest_says() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let policy = world.policy();
    for (name, version, role) in [
        ("documents", "0.1.0", "app"),
        ("photo-viewer", "0.1.1", "app"),
        ("photo-viewer", "0.1.0", "viewer"),
    ] {
        let claim = claim_by(&world.publisher, &dir, name, version, role);
        assert_eq!(
            refused(admit(&dir, &claim, &policy, &[], &world.store(), NOW)),
            "claim_manifest_mismatch",
            "{name} {version} {role}"
        );
    }

    // A manifest that is not JSON, or a version that is not semver.
    std::fs::write(dir.join("capsule.json"), b"not json").unwrap();
    let claim = world.claim(&dir, "0.1.0");
    assert_eq!(
        refused(admit(&dir, &claim, &policy, &[], &world.store(), NOW)),
        "claim_malformed"
    );
    write_manifest(&dir, "photo-viewer", "1.0", "app", None);
    let claim = world.claim(&dir, "1.0");
    assert_eq!(
        refused(admit(&dir, &claim, &policy, &[], &world.store(), NOW)),
        "claim_malformed"
    );
}

// ---- The trust policy ----

#[test]
fn the_release_policy_must_be_signed_by_the_pinned_root() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();

    let by_other = world.release().sign(&sign::generate());
    assert_eq!(
        refused(effective_policy(
            &by_other,
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "policy_signature_invalid"
    );

    // Names the root but is signed by someone else.
    let mut claims_root = world.release().sign(&sign::generate());
    claims_root.signer_did = root_did.clone();
    assert_eq!(
        refused(effective_policy(
            &claims_root,
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "policy_signature_invalid"
    );

    // A publisher added after signing.
    let mut widened = world.release().sign(&world.release_root);
    widened.policy.publishers.push(PublisherEntry {
        did: sign::did(&sign::generate()),
        roles: vec!["system".into()],
        names: None,
    });
    assert_eq!(
        refused(effective_policy(
            &widened,
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "policy_signature_invalid"
    );

    // A revocation removed after signing.
    let mut release = world.release();
    release.revoked_dids.push(sign::did(&sign::generate()));
    let mut unrevoked = release.sign(&world.release_root);
    unrevoked.policy.revoked_dids.clear();
    assert_eq!(
        refused(effective_policy(
            &unrevoked,
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "policy_signature_invalid"
    );

    let good = world.release().sign(&world.release_root);
    let parsed = SignedReleasePolicy::parse(&serde_json::to_vec(&good).unwrap()).unwrap();
    assert!(effective_policy(&parsed, &root_did, &local, NOW, &world.floor()).is_ok());
}

#[test]
fn an_older_policy_cannot_be_replayed_after_a_revocation() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();
    let floor_path = world.root.path().join("device-floor");
    let floor = PolicyFloor::at(&floor_path);
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");

    let before = world.release().sign(&world.release_root);
    let mut revoking = world.release();
    revoking.sequence = 2;
    revoking.revoked_dids.push(sign::did(&world.publisher));
    let revoking = revoking.sign(&world.release_root);

    effective_policy(&before, &root_did, &local, NOW, &floor).unwrap();
    let current = effective_policy(&revoking, &root_did, &local, NOW, &floor).unwrap();
    assert_eq!(
        refused(admit(&dir, &claim, &current, &[], &world.store(), NOW)),
        "publisher_revoked"
    );

    // The policy from before the revocation is genuine and current, and refused.
    assert_eq!(
        refused(effective_policy(&before, &root_did, &local, NOW, &floor)),
        "policy_rollback"
    );
    // The same policy again is fine; so is a higher one.
    effective_policy(&revoking, &root_did, &local, NOW, &floor).unwrap();
    // The floor survives a restart.
    let restarted = PolicyFloor::at(&floor_path);
    assert_eq!(
        restarted.seen().unwrap().map(|(sequence, _)| sequence),
        Some(2)
    );
    assert_eq!(
        refused(effective_policy(
            &before, &root_did, &local, NOW, &restarted
        )),
        "policy_rollback"
    );
    let mut later = world.release();
    later.sequence = 3;
    effective_policy(
        &later.sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &restarted,
    )
    .unwrap();
    assert_eq!(
        restarted.seen().unwrap().map(|(sequence, _)| sequence),
        Some(3)
    );
}

#[test]
fn two_policies_loaded_at_once_never_lower_the_floor() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let first = world.release().sign(&world.release_root);
    let mut second = world.release();
    second.sequence = 2;
    let second = second.sign(&world.release_root);
    for round in 0..200 {
        let path = world.root.path().join(format!("race-{round}"));
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            for release in [&first, &second] {
                let (barrier, path, root_did) = (&barrier, &path, &root_did);
                scope.spawn(move || {
                    barrier.wait();
                    // Either may be refused (the lower one, if it loses).
                    let _ = effective_policy(
                        release,
                        root_did,
                        &LocalConfig::default(),
                        NOW,
                        &PolicyFloor::at(path),
                    );
                });
            }
        });
        let floor = PolicyFloor::at(&path);
        assert_eq!(
            floor.seen().unwrap().map(|(sequence, _)| sequence),
            Some(2),
            "round {round}"
        );
        assert_eq!(
            refused(effective_policy(
                &first,
                &root_did,
                &LocalConfig::default(),
                NOW,
                &floor
            )),
            "policy_rollback",
            "round {round}"
        );
    }
}

#[test]
fn a_policy_held_from_before_a_revocation_does_not_admit() {
    // Codex's case: cache sequence 1, accept sequence 2 revoking the
    // publisher, then admit with the cached policy.
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();
    let floor = world.floor();
    let cached = effective_policy(
        &world.release().sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &floor,
    )
    .unwrap();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");

    let mut revoking = world.release();
    revoking.sequence = 2;
    revoking.revoked_dids.push(sign::did(&world.publisher));
    let current = effective_policy(
        &revoking.sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &floor,
    )
    .unwrap();
    assert_eq!(
        refused(admit(&dir, &claim, &cached, &[], &world.store(), NOW)),
        "policy_stale"
    );
    assert_eq!(
        refused(admit(&dir, &claim, &current, &[], &world.store(), NOW)),
        "publisher_revoked"
    );
    assert!(!world.store().exists(), "nothing was staged");

    // A floor that is gone is not "nothing newer".
    std::fs::remove_file(world.root.path().join("floor-1")).unwrap();
    assert_eq!(
        refused(admit(&dir, &claim, &current, &[], &world.store(), NOW)),
        "policy_stale"
    );
}

#[test]
fn one_sequence_names_one_policy() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();
    let floor = world.floor();
    effective_policy(
        &world.release().sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &floor,
    )
    .unwrap();

    let mut other = world.release();
    other.publishers[0].roles.push("system".into());
    assert_eq!(
        refused(effective_policy(
            &other.sign(&world.release_root),
            &root_did,
            &local,
            NOW,
            &floor
        )),
        "policy_sequence_conflict"
    );
}

#[test]
fn a_policy_that_is_refused_does_not_move_the_floor() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();
    let floor = world.floor();

    let mut expired = world.release();
    expired.sequence = 9;
    expired.expires_at = NOW;
    assert_eq!(
        refused(effective_policy(
            &expired.sign(&world.release_root),
            &root_did,
            &local,
            NOW,
            &floor
        )),
        "policy_expired"
    );
    let mut forged = world.release();
    forged.sequence = 9;
    assert_eq!(
        refused(effective_policy(
            &forged.sign(&sign::generate()),
            &root_did,
            &local,
            NOW,
            &floor
        )),
        "policy_signature_invalid"
    );
    assert_eq!(floor.seen().unwrap(), None);

    let mut next = world.release();
    next.sequence = 2;
    effective_policy(
        &next.sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &floor,
    )
    .unwrap();
    assert_eq!(floor.seen().unwrap().map(|(sequence, _)| sequence), Some(2));
}

#[test]
fn an_expired_policy_is_refused_at_load_and_at_admission() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();

    let mut ends_now = world.release();
    ends_now.expires_at = NOW;
    assert_eq!(
        refused(effective_policy(
            &ends_now.sign(&world.release_root),
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "policy_expired"
    );

    // A policy accepted while current does not admit after it expires.
    let policy = world.policy();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &policy,
            &[],
            &world.store(),
            NOW + HOUR
        )),
        "policy_expired"
    );
    admit(&dir, &claim, &policy, &[], &world.store(), NOW + HOUR - 1).unwrap();
}

#[test]
fn a_policy_floor_that_does_not_parse_is_refused() {
    let world = World::new();
    let path = world.root.path().join("broken-floor");
    std::fs::write(&path, b"sequence 0").unwrap();
    let release = world.release().sign(&world.release_root);
    assert_eq!(
        refused(effective_policy(
            &release,
            &sign::did(&world.release_root),
            &LocalConfig::default(),
            NOW,
            &PolicyFloor::at(&path)
        )),
        "io"
    );
}

#[test]
fn a_dev_key_names_its_capsules_and_expires() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let mut long = world.release();
    long.expires_at = NOW + 10 * HOUR;
    let release = long.sign(&world.release_root);
    let dev = sign::generate();
    let key = |names: Vec<String>, expires_at: u64| LocalConfig {
        dev_mode: true,
        dev_keys: vec![DevKey {
            did: sign::did(&dev),
            roles: vec!["app".into()],
            names,
            expires_at,
        }],
    };

    // Never a whole role.
    assert_eq!(
        refused(effective_policy(
            &release,
            &root_did,
            &key(vec![], NOW + HOUR),
            NOW,
            &world.floor()
        )),
        "dev_key_unscoped"
    );
    let no_names = serde_json::json!({ "dev_mode": true, "dev_keys": [
        { "did": sign::did(&dev), "roles": ["app"], "expires_at": NOW + HOUR }
    ] });
    assert!(serde_json::from_value::<LocalConfig>(no_names).is_err());
    let no_expiry = serde_json::json!({ "dev_mode": true, "dev_keys": [
        { "did": sign::did(&dev), "roles": ["app"], "names": ["photo-viewer"] }
    ] });
    assert!(serde_json::from_value::<LocalConfig>(no_expiry).is_err());

    // Expired when loaded.
    assert_eq!(
        refused(effective_policy(
            &release,
            &root_did,
            &key(vec!["photo-viewer".into()], NOW),
            NOW,
            &world.floor()
        )),
        "dev_key_expired"
    );

    // Expired by the time it is used; the release publisher is not affected.
    let policy = effective_policy(
        &release,
        &root_did,
        &key(vec!["photo-viewer".into()], NOW + HOUR),
        NOW,
        &world.floor(),
    )
    .unwrap();
    let dir = world.capsule("source", "0.1.0");
    let by_dev = claim_by(&dev, &dir, "photo-viewer", "0.1.0", "app");
    admit(&dir, &by_dev, &policy, &[], &world.store(), NOW).unwrap();
    assert_eq!(
        refused(admit(
            &dir,
            &by_dev,
            &policy,
            &[],
            &world.store(),
            NOW + 2 * HOUR
        )),
        "dev_key_expired"
    );
    admit(
        &dir,
        &world.claim(&dir, "0.1.0"),
        &policy,
        &[],
        &world.store(),
        NOW + 2 * HOUR,
    )
    .unwrap();
}

#[test]
fn a_release_policy_runs_at_most_90_days() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let local = LocalConfig::default();
    assert_eq!(MAX_POLICY_LIFETIME_SECS, 90 * 24 * HOUR);
    let floor = world.floor();

    let mut too_long = world.release();
    too_long.sequence = 9;
    too_long.expires_at = NOW + MAX_POLICY_LIFETIME_SECS + 1;
    assert_eq!(
        refused(effective_policy(
            &too_long.sign(&world.release_root),
            &root_did,
            &local,
            NOW,
            &floor
        )),
        "policy_lifetime_too_long"
    );
    let mut forever = world.release();
    forever.expires_at = u64::MAX;
    assert_eq!(
        refused(effective_policy(
            &forever.sign(&world.release_root),
            &root_did,
            &local,
            NOW,
            &floor
        )),
        "policy_lifetime_too_long"
    );
    // Refused, so the floor did not move.
    assert_eq!(floor.seen().unwrap(), None);

    let mut longest = world.release();
    longest.expires_at = NOW + MAX_POLICY_LIFETIME_SECS;
    effective_policy(
        &longest.sign(&world.release_root),
        &root_did,
        &local,
        NOW,
        &floor,
    )
    .unwrap();
}

#[test]
fn a_dev_key_runs_at_most_30_days() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let release = world.release().sign(&world.release_root);
    assert_eq!(MAX_DEV_KEY_LIFETIME_SECS, 30 * 24 * HOUR);
    let key = |expires_at: u64| LocalConfig {
        dev_mode: true,
        dev_keys: vec![DevKey {
            did: sign::did(&sign::generate()),
            roles: vec!["app".into()],
            names: vec!["photo-viewer".into()],
            expires_at,
        }],
    };
    for expires_at in [NOW + MAX_DEV_KEY_LIFETIME_SECS + 1, u64::MAX] {
        assert_eq!(
            refused(effective_policy(
                &release,
                &root_did,
                &key(expires_at),
                NOW,
                &world.floor()
            )),
            "dev_key_lifetime_too_long"
        );
    }
    effective_policy(
        &release,
        &root_did,
        &key(NOW + MAX_DEV_KEY_LIFETIME_SECS),
        NOW,
        &world.floor(),
    )
    .unwrap();
}

#[test]
fn local_config_adds_a_dev_key_only_in_dev_mode() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let release = world.release().sign(&world.release_root);
    let dev = sign::generate();
    let dev_entry = DevKey {
        did: sign::did(&dev),
        roles: vec!["app".into()],
        names: vec!["photo-viewer".into()],
        expires_at: NOW + HOUR,
    };

    let off = LocalConfig {
        dev_mode: false,
        dev_keys: vec![dev_entry.clone()],
    };
    assert_eq!(
        refused(effective_policy(
            &release,
            &root_did,
            &off,
            NOW,
            &world.floor()
        )),
        "dev_key_outside_dev_mode"
    );

    let on = LocalConfig {
        dev_mode: true,
        dev_keys: vec![dev_entry.clone()],
    };
    let policy = effective_policy(&release, &root_did, &on, NOW, &world.floor()).unwrap();
    let dir = world.capsule("source", "0.1.0");
    let claim = claim_by(&dev, &dir, "photo-viewer", "0.1.0", "app");
    admit(&dir, &claim, &policy, &[], &world.store(), NOW).unwrap();

    // The dev key ships only what it lists.
    let other = world.capsule("other", "0.1.0");
    write_manifest(&other, "documents", "0.1.0", "app", None);
    let claim = claim_by(&dev, &other, "documents", "0.1.0", "app");
    assert_eq!(
        refused(admit(&other, &claim, &policy, &[], &world.store(), NOW)),
        "publisher_role_refused"
    );

    // Local config holds nothing else: no revocations, no release publishers.
    let lifted = serde_json::json!({ "dev_mode": true, "dev_keys": [], "revoked_dids": [] });
    assert!(serde_json::from_value::<LocalConfig>(lifted).is_err());
    let publishers = serde_json::json!({ "dev_mode": true, "publishers": [] });
    assert!(serde_json::from_value::<LocalConfig>(publishers).is_err());
}

#[test]
fn a_dev_key_cannot_stand_in_for_a_release_key() {
    let world = World::new();
    let root_did = sign::did(&world.release_root);
    let revoked = sign::generate();
    let mut release = world.release();
    release.revoked_dids.push(sign::did(&revoked));
    let release = release.sign(&world.release_root);
    let entry = |did: String| DevKey {
        did,
        roles: vec!["system".into()],
        names: vec!["home".into()],
        expires_at: NOW + HOUR,
    };

    for did in [
        sign::did(&world.publisher),
        root_did.clone(),
        sign::did(&revoked),
    ] {
        let local = LocalConfig {
            dev_mode: true,
            dev_keys: vec![entry(did.clone())],
        };
        assert_eq!(
            refused(effective_policy(
                &release,
                &root_did,
                &local,
                NOW,
                &world.floor()
            )),
            "dev_key_conflict",
            "{did}"
        );
    }
    let twice = sign::did(&sign::generate());
    let local = LocalConfig {
        dev_mode: true,
        dev_keys: vec![entry(twice.clone()), entry(twice)],
    };
    assert_eq!(
        refused(effective_policy(
            &release,
            &root_did,
            &local,
            NOW,
            &world.floor()
        )),
        "dev_key_conflict"
    );
}

#[test]
fn admission_refuses_an_untrusted_publisher_or_a_role_it_may_not_ship() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");

    let stranger = claim_by(&sign::generate(), &dir, "photo-viewer", "0.1.0", "app");
    assert_eq!(
        refused(admit(
            &dir,
            &stranger,
            &world.policy(),
            &[],
            &world.store(),
            NOW
        )),
        "publisher_untrusted"
    );

    let mut viewers_only = world.release();
    viewers_only.publishers[0].roles = vec!["viewer".into()];
    let claim = world.claim(&dir, "0.1.0");
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy_from(viewers_only),
            &[],
            &world.store(),
            NOW
        )),
        "publisher_role_refused"
    );

    let mut named = world.release();
    named.publishers[0].names = Some(vec!["documents".into()]);
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy_from(named),
            &[],
            &world.store(),
            NOW
        )),
        "publisher_role_refused"
    );
    assert!(!world.store().exists());
}

#[test]
fn admission_refuses_a_revoked_publisher_or_a_revoked_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");

    let mut by_did = world.release();
    by_did.revoked_dids.push(sign::did(&world.publisher));
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy_from(by_did),
            &[],
            &world.store(),
            NOW
        )),
        "publisher_revoked"
    );

    let mut by_cid = world.release();
    by_cid.revoked_cids.push(claim.claim.cid.clone());
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy_from(by_cid),
            &[],
            &world.store(),
            NOW
        )),
        "cid_revoked"
    );

    // Revoking one CID leaves the publisher's other releases alone.
    let next = world.capsule("next", "0.1.1");
    let next_claim = world.claim(&next, "0.1.1");
    let mut by_cid = world.release();
    by_cid.revoked_cids.push(claim.claim.cid.clone());
    admit(
        &next,
        &next_claim,
        &world.policy_from(by_cid),
        &[],
        &world.store(),
        NOW,
    )
    .unwrap();

    // A revoked CID that is already staged does not load through admission.
    let mut later = world.release();
    later.revoked_cids.push(next_claim.claim.cid.clone());
    assert_eq!(
        refused(admit(
            &next,
            &next_claim,
            &world.policy_from(later),
            &[],
            &world.store(),
            NOW
        )),
        "cid_revoked"
    );
}

// ---- The inventory ----

#[test]
fn admission_refuses_a_lower_version_of_an_installed_name() {
    let world = World::new();
    let old = world.capsule("old", "0.1.0");
    let claim = world.claim(&old, "0.1.0");
    let have = [installed("photo-viewer", "0.2.0", "bafkreiinstalled")];
    assert_eq!(
        refused(admit(
            &old,
            &claim,
            &world.policy(),
            &have,
            &world.store(),
            NOW
        )),
        "version_downgrade"
    );

    // Pre-release ordering is semver's: 0.2.0-rc.1 is lower than 0.2.0.
    let rc = world.capsule("rc", "0.2.0-rc.1");
    let claim = world.claim(&rc, "0.2.0-rc.1");
    assert_eq!(
        refused(admit(
            &rc,
            &claim,
            &world.policy(),
            &have,
            &world.store(),
            NOW
        )),
        "version_downgrade"
    );

    // Other names do not count; a higher version admits.
    let others = [installed("documents", "9.0.0", "bafkreiother")];
    admit(
        &old,
        &world.claim(&old, "0.1.0"),
        &world.policy(),
        &others,
        &world.store(),
        NOW,
    )
    .unwrap();
    let new = world.capsule("new", "0.3.0");
    admit(
        &new,
        &world.claim(&new, "0.3.0"),
        &world.policy(),
        &have,
        &world.store(),
        NOW,
    )
    .unwrap();
}

#[test]
fn one_version_of_a_name_has_one_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.2.0");
    let claim = world.claim(&dir, "0.2.0");
    let have = [installed("photo-viewer", "0.2.0", "bafkreiinstalled")];
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy(),
            &have,
            &world.store(),
            NOW
        )),
        "version_conflict"
    );

    // The same CID again is the same capsule.
    let first = admit(&dir, &claim, &world.policy(), &[], &world.store(), NOW).unwrap();
    let have = [installed("photo-viewer", "0.2.0", &first.cid)];
    let again = admit(&dir, &claim, &world.policy(), &have, &world.store(), NOW).unwrap();
    assert_eq!(again, first);
}

#[test]
fn an_installed_version_that_is_not_semver_is_refused() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let have = [installed("photo-viewer", "latest", "bafkreiinstalled")];
    assert_eq!(
        refused(admit(
            &dir,
            &world.claim(&dir, "0.1.0"),
            &world.policy(),
            &have,
            &world.store(),
            NOW
        )),
        "claim_malformed"
    );
}

// ---- Staging by CID ----

#[test]
fn admission_stages_a_read_only_copy_by_cid_and_loads_only_from_it() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    let admitted = admit(&dir, &claim, &world.policy(), &[], &world.store(), NOW).unwrap();

    assert_eq!(admitted.cid, claim.claim.cid);
    assert_eq!(admitted.path, world.store().join(&admitted.cid));
    assert_eq!(
        (
            admitted.name.as_str(),
            admitted.version.as_str(),
            admitted.role.as_str()
        ),
        ("photo-viewer", "0.1.0", "app")
    );
    assert_eq!(mode(&admitted.path), 0o555);
    assert_eq!(mode(&admitted.path.join("icons")), 0o555);
    assert_eq!(mode(&admitted.path.join("capsule.json")), 0o444);
    assert_eq!(mode(&admitted.path.join("icons/photos.png")), 0o444);
    let staged: Vec<_> = std::fs::read_dir(world.store())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        staged,
        vec![std::ffi::OsString::from(&admitted.cid)],
        "no staging directory is left"
    );

    // The source can change or go; the staged copy is what loads.
    std::fs::write(dir.join("photo-viewer.component.wasm"), b"\0asm changed").unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let loaded = load(&world.store(), &admitted.cid).unwrap();
    assert_eq!(loaded.path, admitted.path);
    assert_eq!(loaded.manifest["name"], "photo-viewer");
    assert_eq!(loaded.entries.len(), 3);
    assert_eq!(
        std::fs::read(loaded.path.join("photo-viewer.component.wasm")).unwrap(),
        b"\0asm guest 0.1.0"
    );
}

#[test]
fn load_refuses_a_staged_copy_that_is_writable() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let admitted = admit(
        &dir,
        &world.claim(&dir, "0.1.0"),
        &world.policy(),
        &[],
        &world.store(),
        NOW,
    )
    .unwrap();

    let file = admitted.path.join("icons/photos.png");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        refused(load(&world.store(), &admitted.cid)),
        "staged_not_read_only"
    );
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o444)).unwrap();

    let sub = admitted.path.join("icons");
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        refused(load(&world.store(), &admitted.cid)),
        "staged_not_read_only"
    );
    std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o555)).unwrap();

    std::fs::set_permissions(&admitted.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        refused(load(&world.store(), &admitted.cid)),
        "staged_not_read_only"
    );
    std::fs::set_permissions(&admitted.path, std::fs::Permissions::from_mode(0o555)).unwrap();

    load(&world.store(), &admitted.cid).unwrap();
}

#[test]
fn load_refuses_a_staged_copy_that_no_longer_hashes_to_its_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    let admitted = admit(&dir, &claim, &world.policy(), &[], &world.store(), NOW).unwrap();

    // Opened, changed and sealed again.
    let wasm = admitted.path.join("photo-viewer.component.wasm");
    std::fs::set_permissions(&wasm, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&wasm, b"\0asm swapped").unwrap();
    std::fs::set_permissions(&wasm, std::fs::Permissions::from_mode(0o444)).unwrap();
    assert_eq!(
        refused(load(&world.store(), &admitted.cid)),
        "staged_mismatch"
    );

    // Admission does not trust what is already under the CID either.
    assert_eq!(
        refused(admit(
            &dir,
            &claim,
            &world.policy(),
            &[],
            &world.store(),
            NOW
        )),
        "staged_mismatch"
    );
}

#[test]
fn load_takes_only_a_cid() {
    let world = World::new();
    std::fs::create_dir_all(world.store()).unwrap();
    for name in [
        "",
        "b",
        "../store",
        "bafkrei/../x",
        "Bafkrei",
        "bafkrei1",
        "/etc",
    ] {
        assert_eq!(
            refused(load(&world.store(), name)),
            "path_invalid",
            "{name:?}"
        );
    }
    assert_eq!(refused(load(&world.store(), "bafkreimissing")), "io");
}

// ---- The surface names its core by CID ----

#[test]
fn a_surface_resolves_its_core_by_cid_only() {
    let world = World::new();
    let core = world.capsule("core", "0.1.0");
    let core = admit(
        &core,
        &world.claim(&core, "0.1.0"),
        &world.policy(),
        &[],
        &world.store(),
        NOW,
    )
    .unwrap();
    let have = [installed("photo-viewer", "0.1.0", &core.cid)];
    let requires = |cid: Option<&str>| {
        let mut requirement = serde_json::json!({ "name": "photo-viewer", "kind": "capsule" });
        if let Some(cid) = cid {
            requirement["cid"] = cid.into();
        }
        serde_json::json!({ "requires": [requirement, { "name": "storage", "kind": "provider" }] })
    };

    let found = resolve_requires(&requires(Some(&core.cid)), &have).unwrap();
    assert_eq!(found, have.to_vec());

    assert_eq!(
        refused(resolve_requires(&requires(None), &have)),
        "core_unpinned"
    );
    assert_eq!(
        refused(resolve_requires(&requires(Some("bafkreiother")), &have)),
        "core_mismatch"
    );
    assert_eq!(
        refused(resolve_requires(&requires(Some(&core.cid)), &[])),
        "core_missing"
    );
    // The CID of another name is not the core either.
    let renamed = [installed("documents", "0.1.0", &core.cid)];
    assert_eq!(
        refused(resolve_requires(&requires(Some(&core.cid)), &renamed)),
        "core_mismatch"
    );
}

#[test]
fn the_surface_cid_pins_its_core_cid() {
    let world = World::new();
    let surface = world.dir("surface");
    write_manifest(
        &surface,
        "photos",
        "0.1.0",
        "viewer",
        Some(serde_json::json!([
            { "name": "photo-viewer", "kind": "capsule", "cid": "bafkreione" }
        ])),
    );
    let (one, _) = closure_cid(&surface).unwrap();
    write_manifest(
        &surface,
        "photos",
        "0.1.0",
        "viewer",
        Some(serde_json::json!([
            { "name": "photo-viewer", "kind": "capsule", "cid": "bafkreitwo" }
        ])),
    );
    assert_ne!(closure_cid(&surface).unwrap().0, one);
}

// ---- Provenance ----

#[test]
fn provenance_is_a_separate_record_that_names_the_cid() {
    let world = World::new();
    let dir = world.capsule("source", "0.1.0");
    let claim = world.claim(&dir, "0.1.0");
    let rebuilder = sign::generate();
    let record = Provenance {
        cid: claim.claim.cid.clone(),
        source_commit: "7d8d55f0".into(),
        recipe: "examples/photo-viewer/repro".into(),
        image_digest: "sha256:0000".into(),
        rebuilder_did: sign::did(&rebuilder),
    }
    .sign(&rebuilder);
    let parsed = SignedProvenance::parse(&serde_json::to_vec(&record).unwrap()).unwrap();
    parsed.verify_for(&claim.claim.cid).unwrap();

    // Another rebuilder adds their own for the same CID.
    let second = sign::generate();
    let mut theirs = record.provenance.clone();
    theirs.rebuilder_did = sign::did(&second);
    theirs.sign(&second).verify_for(&claim.claim.cid).unwrap();

    assert_eq!(
        refused(record.verify_for("bafkreiother")),
        "provenance_cid_mismatch"
    );
    let mut changed = record.clone();
    changed.provenance.source_commit = "ffffffff".into();
    assert_eq!(
        refused(changed.verify_for(&claim.claim.cid)),
        "signature_invalid"
    );
    let mut extra = serde_json::to_value(&record).unwrap();
    extra["provenance"]["trusted"] = true.into();
    assert_eq!(
        refused(SignedProvenance::parse(
            &serde_json::to_vec(&extra).unwrap()
        )),
        "claim_malformed"
    );

    // Admission takes no provenance and does not need one.
    admit(&dir, &claim, &world.policy(), &[], &world.store(), NOW).unwrap();
}

/// Capsule kit item 5: a publisher in two entries is refused, not merged, and
/// the refused policy does not move the floor. One entry may list several
/// roles and names.
#[test]
fn a_policy_that_lists_a_publisher_twice_is_refused() {
    let world = World::new();
    let mut release = world.release();
    release.publishers.push(PublisherEntry {
        did: sign::did(&world.publisher),
        roles: vec!["viewer".into()],
        names: Some(vec!["image-viewer".into()]),
    });
    let floor = world.floor();
    let result = effective_policy(
        &release.sign(&world.release_root),
        &sign::did(&world.release_root),
        &LocalConfig::default(),
        NOW,
        &floor,
    );
    assert_eq!(refused(result), "publisher_listed_twice");
    assert_eq!(
        floor.seen().unwrap(),
        None,
        "a refused policy moves no floor"
    );

    let mut release = world.release();
    release.publishers[0].roles = vec!["app".into(), "viewer".into()];
    release.publishers[0].names = Some(vec!["photo-viewer".into(), "image-viewer".into()]);
    let policy = world.policy_from(release);
    assert_eq!(policy.publishers.len(), 1);
    assert_eq!(policy.publishers[0].roles, ["app", "viewer"]);
}
