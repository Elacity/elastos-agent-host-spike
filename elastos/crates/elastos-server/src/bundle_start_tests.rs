//! Tests of the start by CID. Each row goes through `Runtime::run_by_bundle`
//! (or its observed form, which only adds the moment after each walk and a
//! budget a test can reach) on a bundle put into the store by `stage_bundle`,
//! and asserts the exact code of a refusal. The bundles are built here; their CIDs come from the crate,
//! whose own vectors the lab's suite and the staging tests hold to recorded
//! values. Signatures are made by hand (`bundle_admission::tests::signed`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use elastos_compute::providers::{ComponentProvider, SEALED_BRIDGE};
use elastos_storage::providers::LocalFSProvider;

use crate::bundle_admission::tests::{did, file_for, key, sign_by_hand, signed};
use crate::bundle_admission::{
    bundle_signature_path, bundle_slot, BundleRefusal, BUNDLE_MANIFEST_KEYS,
    BUNDLE_SIGNATURE_DOMAIN, BUNDLE_WALK_BUDGET,
};
use crate::runtime::tests::{
    component_manifest_json, component_with_extra_import, quiet_component,
};
use crate::runtime::Runtime;
use crate::stage_cmd::{bundle_cid, stage_bundle};
use elastos_bundle_identity::Budget;

/// One call a component made to the bridge: the capsule's id, the principal
/// it ran for, and the ceiling recorded for it at that moment.
type Call = (String, Option<String>, Option<Vec<String>>);

/// The person the bus fixture component goes on for; for anyone else it ends
/// before it calls the bridge.
const PERSON: &str = "person:local:bus-conformance";

const ENTRYPOINT: &str = "app.component.wasm";

/// A Home with a real component provider, trusting `keys`, never in dev mode.
/// Its bridge handler is set from outside (`set_bridge_hostcall`) and reads no
/// ceiling: it records each call it sees. A capsule started from a folder
/// reaches such a handler (the runtime module's test of the folder start
/// shows that with the same component); a capsule started by CID reaches it
/// only when its manifest has asks, and without asks must not.
struct Home {
    runtime: Arc<Runtime>,
    dir: tempfile::TempDir,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl Home {
    async fn trusting(keys: &[&SigningKey]) -> Home {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            LocalFSProvider::new(dir.path().join("storage"))
                .await
                .unwrap(),
        );
        let runtime = Arc::new(Runtime::with_providers_and_component(
            storage,
            Vec::new(),
            Some(Arc::new(ComponentProvider::new())),
        ));
        let home = Home {
            runtime,
            dir,
            calls: Arc::default(),
        };
        home.trust(keys).await;
        let (seen, bridge) = (home.calls.clone(), Arc::downgrade(&home.runtime));
        home.runtime
            .set_bridge_hostcall(Arc::new(move |_line, capsule_id, principal_id| {
                let ceiling = bridge.upgrade().and_then(|it| it.ceiling_of(capsule_id));
                seen.lock().unwrap().push((
                    capsule_id.to_string(),
                    principal_id.map(ToOwned::to_owned),
                    ceiling,
                ));
                Err("the test's bridge handler was reached".to_string())
            }));
        home
    }

    /// Replace the keys this Home trusts.
    async fn trust(&self, keys: &[&SigningKey]) {
        self.admit(keys, false).await;
    }

    /// Replace the keys this Home trusts and say whether it is in dev mode.
    async fn admit(&self, keys: &[&SigningKey], dev_mode: bool) {
        let keys: Vec<String> = keys
            .iter()
            .map(|key| hex::encode(key.verifying_key().to_bytes()))
            .collect();
        self.runtime
            .configure_capsule_admission(self.dir.path(), &keys, dev_mode)
            .await
            .unwrap();
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    /// A bundle folder holding `manifest` and `component` as its entrypoint.
    fn bundle(&self, name: &str, manifest: &str, component: &[u8]) -> PathBuf {
        let folder = self.dir.path().join("source").join(name);
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("capsule.json"), manifest).unwrap();
        fs::write(folder.join(ENTRYPOINT), component).unwrap();
        folder
    }

    /// Stage `folder` signed by `key`; returns the bundle's CID.
    async fn stage(&self, folder: &Path, key: &SigningKey) -> String {
        let cid = bundle_cid(folder).unwrap();
        let signature = self.dir.path().join(format!("{cid}.by-hand.sig.json"));
        fs::write(&signature, signed(&cid, key)).unwrap();
        let staged = stage_bundle(&self.runtime, &self.data(), folder, &signature)
            .await
            .unwrap();
        assert_eq!(staged.cid, cid);
        cid
    }

    /// Start by CID for `person`; the name that ran and its signer, or the refusal.
    async fn run(
        &self,
        cid: &str,
        person: Option<&str>,
    ) -> Result<(String, String), BundleRefusal> {
        self.runtime
            .run_by_bundle(&self.data(), cid, Vec::new(), person.map(ToOwned::to_owned))
            .await
            .map(|(handle, accepted)| (handle.manifest.name, accepted.signer_did))
    }

    fn slot_file(&self, cid: &str, file: &str) -> PathBuf {
        bundle_slot(&self.data(), &cid.parse().unwrap()).join(file)
    }

    /// Overwrite one of a slot's files, which staging wrote read-only.
    fn overwrite(&self, cid: &str, file: &str, bytes: &[u8]) {
        let path = self.slot_file(cid, file);
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
        fs::write(&path, bytes).unwrap();
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    /// `bundle` and then `stage`: the CID of a staged bundle signed by `key`.
    async fn staged(
        &self,
        folder: &str,
        manifest: &str,
        component: &[u8],
        key: &SigningKey,
    ) -> String {
        let folder = self.bundle(folder, manifest, component);
        self.stage(&folder, key).await
    }

    /// Start by CID under `budget`: the name that ran or the refusal, and
    /// the CID of each bundle the start walked, in the order it walked them.
    async fn run_watched(
        &self,
        cid: &str,
        person: Option<&str>,
        budget: Budget,
    ) -> (Result<String, BundleRefusal>, Vec<String>) {
        let mut walked = Vec::new();
        let person = person.map(ToOwned::to_owned);
        let result = self
            .runtime
            .run_by_bundle_observed(&self.data(), cid, Vec::new(), person, budget, |cid| {
                walked.push(cid.to_string())
            })
            .await
            .map(|(handle, _)| handle.manifest.name);
        (result, walked)
    }
}

/// `manifest(name)` whose requirements pin `pins`: requirement name and CID.
fn manifest_pinning(name: &str, pins: &[(&str, &str)]) -> String {
    let pin = |(name, cid): &(&str, &str)| serde_json::json!({"name": name, "kind": "capsule", "cid": cid});
    let requires: Vec<serde_json::Value> = pins.iter().map(pin).collect();
    manifest_with(name, "requires", requires.into())
}

/// The refusal of a pinned bundle: its requirement's name around its own.
fn under(name: &str, refusal: BundleRefusal) -> BundleRefusal {
    BundleRefusal::Requirement {
        name: name.to_string(),
        refusal: Box::new(refusal),
    }
}

/// The manifest every row starts from: only keys the start by CID takes.
fn manifest(name: &str) -> String {
    component_manifest_json(name)
}

/// `manifest(name)` with one more key, or one key's value replaced.
fn manifest_with(name: &str, key: &str, value: serde_json::Value) -> String {
    let mut json: serde_json::Value = serde_json::from_str(&manifest(name)).unwrap();
    json.as_object_mut().unwrap().insert(key.to_string(), value);
    json.to_string()
}

/// The bus fixture component: it calls the bridge once when it runs for
/// `PERSON`, and ends in an error when that call is refused.
fn calling_component() -> Vec<u8> {
    fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/components/bus-v1/bus-v1-conformance.component.wasm"),
    )
    .unwrap()
}

fn code(result: Result<(String, String), BundleRefusal>) -> &'static str {
    result.expect_err("refused").code()
}

/// R-run, R-nogrant, R-presentation. A staged component starts by its CID and
/// what runs is that component: the quiet one ends well; the calling one,
/// run for its person, makes its one call to the bridge and gets the seal's
/// answer, and the Home's bridge handler never sees that call; run for nobody
/// it ends before any call, with its own words. Nothing is registered with
/// the Runtime as a running capsule, though the manifest sets projections.
#[tokio::test]
async fn a_staged_component_starts_by_its_cid_and_no_bridge_handler_sees_its_calls() {
    let publisher = key(41);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = home.bundle("quiet", &manifest("quiet-by-cid"), &quiet_component());
    let calling = home.bundle("calling", &manifest("calling-by-cid"), &calling_component());
    let quiet = home.stage(&quiet, &publisher).await;
    let calling = home.stage(&calling, &publisher).await;
    assert_ne!(quiet, calling);
    assert!(manifest("x").contains(r#""projections": ["cli"]"#));

    let ran = home.run(&quiet, Some(PERSON)).await.unwrap();
    assert_eq!(
        ran,
        ("quiet-by-cid".to_string(), did(&publisher.verifying_key()))
    );

    let refusal = home.run(&calling, Some(PERSON)).await.unwrap_err();
    assert_eq!(
        refusal.to_string(),
        format!(
            "bundle_start_failed: Compute error: Component capsule denied: BusError::Denied({SEALED_BRIDGE:?})"
        )
    );
    assert_eq!(
        home.calls(),
        Vec::new(),
        "no bridge handler sees a call from a capsule started by CID"
    );
    assert!(home.runtime.list_capsules().await.is_empty());

    // Run for nobody, the calling component ends before any call.
    let refusal = home.run(&calling, None).await.unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "bundle_start_failed: Compute error: Component capsule denied: BusError::Denied(\"Runtime did not bind the conformance principal\")"
    );
    assert_eq!(home.calls(), Vec::new());
}

/// The asks-nothing fixture's bundle folder: a manifest and one component.
fn asks_nothing_bundle() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/components/asks-nothing/bundle")
}

/// The CID of that bundle. Recorded from the lab README's Python rule for a
/// bundle's CID, run over the two committed files, not from the code under
/// test. A machine that stages this folder must print this.
const ASKS_NOTHING_CID: &str = "bafybeifg5dmvip4scwenuyzleucrl4zl2fwfrma7xi7y3pmt544driy4fi";

/// The fixture's binary is what its committed text builds, byte for byte, and
/// that is the quiet component these tests build for themselves; its manifest
/// uses only keys a start by CID takes and names the Runtime's own contract
/// hash; and the bundle's CID is the recorded one.
#[test]
fn the_asks_nothing_fixture_is_its_text_and_has_its_recorded_cid() {
    let bundle = asks_nothing_bundle();
    let text = fs::read_to_string(bundle.join("../asks-nothing.wat")).unwrap();
    let built = wat::parse_str(&text).expect("the fixture's text is a component");
    let committed = fs::read(bundle.join("asks-nothing.component.wasm")).unwrap();
    assert_eq!(
        hex::encode(&committed),
        hex::encode(&built),
        "the committed binary (left) is not what its text builds (right)"
    );
    assert_eq!(built, quiet_component());

    let manifest = fs::read(bundle.join("capsule.json")).unwrap();
    let keys: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
    for key in keys.as_object().unwrap().keys() {
        assert!(BUNDLE_MANIFEST_KEYS.contains(&key.as_str()), "{key}");
    }
    assert_eq!(
        keys["wit_world_sha256"],
        elastos_common::elastos_bus_v1_wit_sha256()
    );
    assert_eq!(keys["entrypoint"], "asks-nothing.component.wasm");
    let mut names: Vec<String> = fs::read_dir(&bundle)
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["asks-nothing.component.wasm", "capsule.json"]);

    assert_eq!(bundle_cid(&bundle).unwrap(), ASKS_NOTHING_CID);
}

/// The fixture, staged as it is committed and started by its CID, ends well:
/// for nobody and for a person alike, with its name and its signer, with no
/// call to any bridge handler and nothing registered as running. This is the
/// run the three-machine receipts repeat with the built binary.
#[tokio::test]
async fn the_asks_nothing_fixture_is_staged_and_started_by_its_cid_and_ends_well() {
    let publisher = key(56);
    let home = Home::trusting(&[&publisher]).await;
    let cid = home.stage(&asks_nothing_bundle(), &publisher).await;
    assert_eq!(cid, ASKS_NOTHING_CID);
    for person in [None, Some(PERSON)] {
        assert_eq!(
            home.run(&cid, person).await.unwrap(),
            ("asks-nothing".to_string(), did(&publisher.verifying_key()))
        );
    }
    assert_eq!(home.calls(), Vec::new());
    assert!(home.runtime.list_capsules().await.is_empty());
}

/// R-signer. After the same bundle is staged again with a second trusted
/// key's signature, a start reports that key: the signer is read from the
/// signature file checked at this start, not remembered from staging.
#[tokio::test]
async fn the_signer_reported_is_the_one_checked_at_this_start() {
    let (first, second) = (key(42), key(43));
    let home = Home::trusting(&[&first, &second]).await;
    let folder = home.bundle("resigned", &manifest("resigned"), &quiet_component());
    let cid = home.stage(&folder, &first).await;
    let (_, signer) = home.run(&cid, None).await.unwrap();
    assert_eq!(signer, did(&first.verifying_key()));

    assert_eq!(home.stage(&folder, &second).await, cid);
    let (_, signer) = home.run(&cid, None).await.unwrap();
    assert_eq!(signer, did(&second.verifying_key()));
}

/// R-changed. One byte of a slot's file changed after staging: the start
/// refuses with the mismatch, naming both CIDs. The changed file is the
/// component, so a start that compiled before comparing would fail another
/// way. The control is the same slot before the change.
#[tokio::test]
async fn a_slot_changed_after_staging_is_refused_as_a_mismatch() {
    let publisher = key(44);
    let home = Home::trusting(&[&publisher]).await;
    let component = quiet_component();
    let folder = home.bundle("changed", &manifest("changed"), &component);
    let cid = home.stage(&folder, &publisher).await;
    home.run(&cid, None).await.unwrap();

    let mut changed = component.clone();
    *changed.last_mut().unwrap() ^= 1;
    home.overwrite(&cid, ENTRYPOINT, &changed);
    let elsewhere = home.bundle("changed-copy", &manifest("changed"), &changed);
    let computed = bundle_cid(&elsewhere).unwrap();
    assert_ne!(computed, cid);
    assert_eq!(
        home.run(&cid, None).await.unwrap_err(),
        BundleRefusal::CidMismatch {
            asked: cid.clone(),
            computed
        }
    );
    assert_eq!(code(home.run(&cid, None).await), "bundle_cid_mismatch");
}

/// R-swap. The slot's component is replaced right after the start's one walk
/// of it. What runs is the component that was walked (it calls the bridge and
/// ends with the seal's answer); the replacement on disk (which calls nothing
/// and would end well) is never read.
#[tokio::test]
async fn a_component_replaced_after_the_walk_does_not_run() {
    let publisher = key(45);
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("swapped", &manifest("swapped"), &calling_component());
    let cid = home.stage(&folder, &publisher).await;
    let replacement = quiet_component();

    let result = home
        .runtime
        .run_by_bundle_observed(
            &home.data(),
            &cid,
            Vec::new(),
            Some(PERSON.to_string()),
            BUNDLE_WALK_BUDGET,
            |_| home.overwrite(&cid, ENTRYPOINT, &replacement),
        )
        .await;

    assert_eq!(
        fs::read(home.slot_file(&cid, ENTRYPOINT)).unwrap(),
        replacement
    );
    let refusal = result
        .map(|(handle, _)| handle.manifest.name)
        .expect_err("the walked component ran");
    assert!(refusal
        .to_string()
        .ends_with(&format!("BusError::Denied({SEALED_BRIDGE:?})")));
    assert_eq!(home.calls(), Vec::new());
}

/// R-sig-gone, and its neighbours: the store is trusted for nothing at a
/// start. With the signature file gone the bundle is unsigned; with the key
/// no longer trusted its signature is not accepted; with no key trusted at
/// all the trust set is empty. The control starts between them.
#[tokio::test]
async fn a_start_checks_the_signature_that_is_there_now_against_the_keys_trusted_now() {
    let (publisher, other) = (key(46), key(47));
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("signed", &manifest("signed"), &quiet_component());
    let cid = home.stage(&folder, &publisher).await;
    home.run(&cid, None).await.unwrap();

    home.trust(&[&other]).await;
    assert_eq!(
        code(home.run(&cid, None).await),
        "bundle_signature_not_accepted"
    );
    home.trust(&[]).await;
    assert_eq!(code(home.run(&cid, None).await), "bundle_trust_set_empty");
    home.trust(&[&publisher]).await;
    home.run(&cid, None).await.unwrap();

    // The key is still trusted, and the file beside the slot no longer holds
    // its signature over this CID: one character of it changed; then a good
    // signature by the same key over another text.
    let file = bundle_signature_path(&home.data(), &cid.parse().unwrap());
    let good = fs::read(&file).unwrap();
    let signer = did(&publisher.verifying_key());
    let signature = sign_by_hand(&publisher, BUNDLE_SIGNATURE_DOMAIN, &cid);
    let flipped = if signature.starts_with('0') { "1" } else { "0" };
    let tampered = format!("{flipped}{}", &signature[1..]);
    let over_another = sign_by_hand(&publisher, BUNDLE_SIGNATURE_DOMAIN, "another text");
    for signature in [tampered, over_another] {
        fs::write(&file, file_for(&cid, &signer, &signature)).unwrap();
        assert_eq!(
            code(home.run(&cid, None).await),
            "bundle_signature_not_accepted"
        );
    }
    fs::write(&file, good).unwrap();
    home.run(&cid, None).await.unwrap();

    // Dev mode, which lets a start from a folder run an unsigned capsule,
    // relaxes none of this: no signature file, no trusted key, a key that is
    // not the signer's.
    fs::remove_file(&file).unwrap();
    assert_eq!(code(home.run(&cid, None).await), "bundle_unsigned");
    home.admit(&[&publisher], true).await;
    assert_eq!(code(home.run(&cid, None).await), "bundle_unsigned");
    fs::write(&file, signed(&cid, &publisher)).unwrap();
    home.admit(&[], true).await;
    assert_eq!(code(home.run(&cid, None).await), "bundle_trust_set_empty");
    home.admit(&[&other], true).await;
    assert_eq!(
        code(home.run(&cid, None).await),
        "bundle_signature_not_accepted"
    );
    home.admit(&[&publisher], true).await;
    home.run(&cid, None).await.unwrap();
}

/// R-presentation. A manifest that sets all three presentation keys starts by
/// CID, and nothing is registered with the Runtime as running: no window, no
/// projection. The control has none of the three and behaves the same.
#[tokio::test]
async fn a_manifest_with_presentation_keys_starts_and_registers_nothing() {
    let publisher = key(55);
    let home = Home::trusting(&[&publisher]).await;
    let mut json: serde_json::Value = serde_json::from_str(&manifest("presented")).unwrap();
    let keys = json.as_object_mut().unwrap();
    keys.insert("projections".into(), serde_json::json!(["cli", "web"]));
    keys.insert("window_policy".into(), serde_json::json!("multiple"));
    keys.insert("icon".into(), serde_json::json!("icons"));
    let presented = home.bundle("presented", &json.to_string(), &quiet_component());
    let keys = json.as_object_mut().unwrap();
    for key in ["projections", "window_policy", "icon"] {
        assert!(BUNDLE_MANIFEST_KEYS.contains(&key));
        keys.remove(key).unwrap();
    }
    let plain = home.bundle("plain", &json.to_string(), &quiet_component());
    for folder in [presented, plain] {
        let cid = home.stage(&folder, &publisher).await;
        assert_eq!(home.run(&cid, None).await.unwrap().0, "presented");
        assert!(home.runtime.list_capsules().await.is_empty());
    }
    assert_eq!(home.calls(), Vec::new());
}

/// R-agent to R-signed-inside: one row per key that a start by CID does not
/// take. Each bundle is valid and signed and is staged (staging stores bytes
/// and grants nothing); it differs from the control only by that one key,
/// present with the emptiest value its type allows. Each is refused by the
/// one code, naming exactly that key, and nothing runs.
#[tokio::test]
async fn each_key_outside_the_list_is_refused_by_name() {
    let publisher = key(48);
    let home = Home::trusting(&[&publisher]).await;
    let null = serde_json::Value::Null;
    let rows = [
        ("agent", null.clone()),
        ("capabilities", serde_json::json!([])),
        ("permissions", serde_json::json!({})),
        ("provides", null.clone()),
        ("providers", null.clone()),
        ("authority", null.clone()),
        ("interfaces", serde_json::json!([])),
        ("microvm", null.clone()),
        ("viewer", null.clone()),
        ("model_content", null.clone()),
        ("signature", null.clone()),
    ];
    for (key, value) in rows {
        assert!(!BUNDLE_MANIFEST_KEYS.contains(&key), "{key}");
        let name = format!("with-{key}");
        let folder = home.bundle(&name, &manifest_with(&name, key, value), &quiet_component());
        let cid = home.stage(&folder, &publisher).await;
        let refusal = home.run(&cid, None).await.unwrap_err();
        assert_eq!(
            refusal.to_string(),
            format!("bundle_manifest_field_refused: {key}")
        );

        let control = home.bundle(
            &format!("without-{key}"),
            &manifest(&name),
            &quiet_component(),
        );
        let control = home.stage(&control, &publisher).await;
        assert_eq!(home.run(&control, None).await.unwrap().0, name);
    }
    assert_eq!(home.calls(), Vec::new());
}

/// R-ceiling. The ceiling of a capsule started by CID is filled, as every
/// capsule's is, from the one bounds function, and for every manifest this
/// start admits that is the manifest's asks and nothing else. Without asks
/// the ceiling is empty: shown for the base manifest and for one that sets
/// every other key on the list. With asks it is exactly those asks, each
/// with its actions. So "no asks" and "an empty ceiling" are one thing
/// here, which is what the start seals by. The control is a manifest with a
/// capability: its ceiling is not empty, and this start refuses it, also
/// when asks stand beside it.
#[test]
fn the_ceiling_of_a_manifest_this_start_admits_is_its_asks() {
    use crate::bundle_admission::admit_bundle_manifest;
    use elastos_bundle_identity::checked_bundle_within as walk;
    let dir = tempfile::tempdir().unwrap();
    let bundle = |name: &str, manifest: &str| {
        let folder = dir.path().join(name);
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("capsule.json"), manifest).unwrap();
        fs::write(folder.join(ENTRYPOINT), quiet_component()).unwrap();
        walk(&folder, BUNDLE_WALK_BUDGET).unwrap()
    };
    let mut full: serde_json::Value = serde_json::from_str(&manifest("full")).unwrap();
    let keys = full.as_object_mut().unwrap();
    keys.insert("description".into(), serde_json::json!("every allowed key"));
    keys.insert("author".into(), serde_json::json!("a test"));
    keys.insert("projections".into(), serde_json::json!(["cli", "web"]));
    keys.insert("window_policy".into(), serde_json::json!("multiple"));
    keys.insert("icon".into(), serde_json::json!("icons"));
    keys.insert(
        "resources".into(),
        serde_json::json!({"memory_mb": 64, "cpu_shares": 2}),
    );
    // A pinned requirement is no authority: it adds nothing to the ceiling.
    keys.insert(
        "requires".into(),
        serde_json::json!([{"name": "needed", "kind": "capsule", "cid": ASKS_NOTHING_CID}]),
    );
    let written: Vec<&str> = keys.keys().map(String::as_str).collect();
    for key in BUNDLE_MANIFEST_KEYS
        .into_iter()
        .filter(|key| *key != "asks")
    {
        assert!(written.contains(&key), "{key} is not set in this row");
    }
    for (name, json) in [("base", manifest("base")), ("full", full.to_string())] {
        let admitted = admit_bundle_manifest(&bundle(name, &json)).unwrap();
        assert!(admitted.manifest.asks.is_empty(), "{name}");
        assert_eq!(
            admitted.manifest.resource_authority_bounds(),
            Vec::<String>::new(),
            "{name}"
        );
    }

    full["asks"] = serde_json::json!([
        {"resource": "elastos://did/*", "actions": ["read"]},
        {"resource": "localhost://Users/self/Documents/*", "actions": ["read", "write"]}
    ]);
    for key in BUNDLE_MANIFEST_KEYS {
        assert!(full.get(key).is_some(), "{key} is not set in this row");
    }
    let admitted = admit_bundle_manifest(&bundle("asking", &full.to_string())).unwrap();
    assert!(!admitted.manifest.asks.is_empty());
    let ceiling = admitted.manifest.resource_authority_bounds();
    let shown: Vec<String> = ceiling.iter().map(ToString::to_string).collect();
    assert_eq!(
        shown,
        [
            "elastos://did/* [read]",
            "localhost://Users/self/Documents/* [read, write]"
        ]
    );

    let capable = manifest_with(
        "capable",
        "capabilities",
        serde_json::json!(["elastos://did/*"]),
    );
    let walked = bundle("capable", &capable);
    let typed: elastos_common::CapsuleManifest = serde_json::from_str(&capable).unwrap();
    assert_eq!(typed.resource_authority_bounds(), ["elastos://did/*"]);
    assert_eq!(
        admit_bundle_manifest(&walked).unwrap_err().to_string(),
        "bundle_manifest_field_refused: capabilities"
    );
    // The manifest type refuses asks beside a capability, so the walk
    // refuses such a bundle before the key list is asked.
    full["capabilities"] = serde_json::json!(["elastos://did/*"]);
    let folder = dir.path().join("both");
    fs::create_dir_all(&folder).unwrap();
    fs::write(folder.join("capsule.json"), full.to_string()).unwrap();
    fs::write(folder.join(ENTRYPOINT), quiet_component()).unwrap();
    let refusal = walk(&folder, BUNDLE_WALK_BUDGET).unwrap_err();
    assert!(refusal.to_string().contains("asks_conflict"), "{refusal}");
}

/// The list holds every key the base manifest uses, and the two lists
/// together are every key of the Runtime's manifest type: a key added to
/// that type appears in neither and fails this test until it is placed.
#[test]
fn the_list_and_the_refused_keys_cover_the_manifest_type() {
    let refused = [
        "agent",
        "capabilities",
        "permissions",
        "provides",
        "providers",
        "authority",
        "interfaces",
        "microvm",
        "viewer",
        "model_content",
        "signature",
    ];
    let source = include_str!("../../elastos-common/src/manifest.rs");
    let start = source.find("pub struct CapsuleManifest {").unwrap();
    let body = &source[start..start + source[start..].find("\n}\n").unwrap()];
    let mut fields = Vec::new();
    let mut renamed: Option<String> = None;
    for line in body.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("#[serde(rename = \"") {
            renamed = Some(rest.split('"').next().unwrap().to_string());
        } else if line.starts_with("pub struct ") {
            continue;
        } else if let Some(rest) = line.strip_prefix("pub ") {
            let field = rest.split(':').next().unwrap().to_string();
            fields.push(renamed.take().unwrap_or(field));
        }
    }
    fields.sort();
    let mut placed: Vec<String> = BUNDLE_MANIFEST_KEYS
        .iter()
        .chain(refused.iter())
        .map(ToString::to_string)
        .collect();
    placed.sort();
    assert_eq!(fields, placed);
}

/// R-unknown-field, as the code has it: a key the manifest type does not know
/// never reaches the list, because the walk parses the manifest with that
/// type first and refuses it under its own code, naming the key. Staging
/// refuses such a bundle, so the slot is written here by hand.
#[tokio::test]
async fn a_key_the_manifest_type_does_not_know_is_refused_by_the_walk() {
    let publisher = key(49);
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("known", &manifest("known"), &quiet_component());
    let cid = home.stage(&folder, &publisher).await;

    let unknown = manifest_with("known", "lab_cid", serde_json::json!("x"));
    home.overwrite(&cid, "capsule.json", unknown.as_bytes());
    let refusal = home.run(&cid, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_walk_manifest_unparsed");
    assert!(
        refusal.to_string().contains("unknown field `lab_cid`"),
        "{refusal}"
    );
}

/// R-resources. `resources` is on the list and has no effect on this path:
/// the component provider's limits are its own. Shown by a component whose
/// memory starts at 2 MiB under a manifest that says 1 MiB: it starts.
#[tokio::test]
async fn resources_are_taken_and_are_not_a_limit_on_this_path() {
    let publisher = key(50);
    let home = Home::trusting(&[&publisher]).await;
    let component = wat::parse_str(QUIET_WAT.replace("\"memory\") 1)", "\"memory\") 32)")).unwrap();
    assert_ne!(component, wat::parse_str(QUIET_WAT).unwrap());
    let resources = serde_json::json!({"memory_mb": 1, "cpu_shares": 1});
    let folder = home.bundle(
        "resources",
        &manifest_with("resources", "resources", resources),
        &component,
    );
    let cid = home.stage(&folder, &publisher).await;
    assert_eq!(home.run(&cid, None).await.unwrap().0, "resources");
}

/// The quiet component's text, for the row that changes its memory.
const QUIET_WAT: &str = r#"(component
  (import "elastos:bus/types@1.0.0" (instance $types
    (type $error (variant
      (case "denied" string) (case "not-found" string) (case "invalid" string)
      (case "unavailable" string) (case "timeout" string) (case "internal" string)))
    (export "bus-error" (type (eq $error)))))
  (alias export $types "bus-error" (type $bus-error))
  (core module $m
    (memory (export "memory") 1)
    (func (export "run") (result i32) (i32.const 0)))
  (core instance $i (instantiate $m))
  (func $run (result (result (error $bus-error)))
    (canon lift (core func $i "run") (memory $i "memory")))
  (instance $lifecycle (export "run" (func $run)))
  (export "elastos:bus/lifecycle@1.0.0" (instance $lifecycle)))"#;

/// R-not-component, and the two neighbours that end under the same code or
/// the manifest's: another role; a component that imports outside the
/// contract; an entrypoint that is not one of the bundle's files.
#[tokio::test]
async fn what_is_not_an_app_component_of_the_contract_is_refused() {
    let publisher = key(51);
    let home = Home::trusting(&[&publisher]).await;

    let viewer = manifest_with("a-viewer", "role", serde_json::json!("viewer"));
    let folder = home.bundle("viewer", &viewer, &quiet_component());
    let cid = home.stage(&folder, &publisher).await;
    assert_eq!(code(home.run(&cid, None).await), "bundle_not_a_component");

    let folder = home.bundle(
        "imports",
        &manifest("imports"),
        &component_with_extra_import(),
    );
    let cid = home.stage(&folder, &publisher).await;
    let refusal = home.run(&cid, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_not_a_component");
    assert!(refusal.to_string().contains("wasi:filesystem"), "{refusal}");

    let elsewhere = manifest_with("elsewhere", "entrypoint", serde_json::json!("other.wasm"));
    let folder = home.bundle("elsewhere", &elsewhere, &quiet_component());
    let cid = home.stage(&folder, &publisher).await;
    assert_eq!(
        home.run(&cid, None).await.unwrap_err().to_string(),
        "bundle_manifest_invalid: entrypoint \"other.wasm\" is not a file of the bundle"
    );
    assert_eq!(home.calls(), Vec::new());
}

/// R-old-cid, the store's half: a CID the store has no slot for is
/// `bundle_missing`, and text that is not a bundle's CID is refused for its
/// form before the store is looked at. Neither fetches: see the next test.
#[tokio::test]
async fn a_missing_slot_and_a_bad_cid_are_refused() {
    let home = Home::trusting(&[&key(52)]).await;
    let absent = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
    assert_eq!(
        home.run(absent, None).await.unwrap_err(),
        BundleRefusal::Missing(absent.to_string())
    );
    for text in ["", "not-a-cid", &absent.to_uppercase(), "../../etc"] {
        assert_eq!(
            code(home.run(text, None).await),
            "bundle_cid_form_invalid",
            "{text}"
        );
    }
    assert!(
        !home.data().join("capsules").exists(),
        "nothing was made in the store"
    );

    // A store that cannot be looked into is not "no such bundle": here the
    // store's folder is a file.
    fs::create_dir_all(home.data().join("capsules")).unwrap();
    fs::write(home.data().join("capsules").join("by-cid"), b"not a folder").unwrap();
    assert_eq!(code(home.run(absent, None).await), "bundle_store_io");
}

/// The slot is a symbolic link to a folder that holds the same bundle. The
/// walk does not follow it: the start is refused by the walk, whatever the
/// link points at.
#[cfg(unix)]
#[tokio::test]
async fn a_slot_that_is_a_symbolic_link_is_not_followed() {
    let publisher = key(53);
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("linked", &manifest("linked"), &quiet_component());
    let cid = home.stage(&folder, &publisher).await;
    home.run(&cid, None).await.unwrap();

    let slot = bundle_slot(&home.data(), &cid.parse().unwrap());
    let moved = home.dir.path().join("moved-slot");
    fs::rename(&slot, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &slot).unwrap();
    let refusal = home.run(&cid, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_walk_unreadable", "{refusal}");
}

/// A Runtime with no component provider admits the bundle and then cannot
/// start it: the one code for what comes after admission.
#[tokio::test]
async fn a_runtime_without_a_component_provider_cannot_start_a_bundle() {
    let publisher = key(54);
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("no-provider", &manifest("no-provider"), &quiet_component());
    let cid = home.stage(&folder, &publisher).await;

    let (bare, _dir) = crate::runtime::tests::test_runtime().await;
    bare.configure_capsule_admission(
        home.dir.path(),
        &[hex::encode(publisher.verifying_key().to_bytes())],
        false,
    )
    .await
    .unwrap();
    let refusal = bare
        .run_by_bundle(&home.data(), &cid, Vec::new(), None)
        .await
        .map(|(handle, _)| handle.manifest.name)
        .unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "bundle_start_failed: No component compute provider is configured"
    );
}

/// The bridge looks a ceiling up by the calling capsule's own id, and an id
/// it holds no entry for gets the empty ceiling, never another capsule's. A
/// text pin of the one lookup in the Home's bridge handler; that an empty
/// ceiling lets no word through is the bridge's own test
/// (`a_manifest_with_asks_is_held_to_their_resources_and_their_actions`).
#[test]
fn a_capsule_the_bridge_holds_no_ceiling_for_gets_the_empty_one() {
    let source = include_str!("runtime.rs");
    let handler = &source[source.find("component.set_bus_hostcall(Arc::new(").unwrap()..];
    let handler = &handler[..handler.find("\n            }));\n").unwrap()];
    let lookup = "let manifest_capabilities = host_manifest_capabilities\n                    \
                  .read()\n                    \
                  .ok()\n                    \
                  .and_then(|guard| guard.get(capsule_id).cloned())\n                    \
                  .unwrap_or_default();";
    assert_eq!(handler.matches(lookup).count(), 1);
    // The handler reads the map of ceilings there and nowhere else, and what
    // it read is the ceiling the request is judged under.
    assert_eq!(handler.matches("host_manifest_capabilities").count(), 1);
    assert_eq!(handler.matches("manifest_capabilities,\n").count(), 1);
    // The content of a launch is looked up the same way: by the caller's own
    // id, there and nowhere else, and a caller with no entry gets none.
    let held = "let launch = host_launch_contents\n                    \
                .read()\n                    \
                .unwrap_or_else(|it| it.into_inner());\n                \
                let launch = launch.get(capsule_id).cloned();";
    assert_eq!(handler.matches(held).count(), 1);
    assert_eq!(handler.matches("host_launch_contents").count(), 1);
    assert_eq!(handler.matches("launch,\n").count(), 1);
}

/// A-asks. A capsule whose manifest has asks is started unsealed, under
/// those asks. The calling component, run for its person, reaches the Home's
/// bridge handler with its one call; at that moment its ceiling is its asks,
/// each with its actions; afterwards no ceiling is left. The control is the
/// same component with no asks: it is sealed, and the handler sees nothing.
#[tokio::test]
async fn a_capsule_with_asks_is_started_unsealed_under_its_asks() {
    let publisher = key(69);
    let home = Home::trusting(&[&publisher]).await;
    let asks = serde_json::json!([
        {"resource": "elastos://test/bus/probe", "actions": ["read"]},
        {"resource": "localhost://Users/self/Documents/*", "actions": ["read", "write"]}
    ]);
    let asking = manifest_with("asking", "asks", asks);
    let asking = home
        .staged("asking", &asking, &calling_component(), &publisher)
        .await;
    let silent = home
        .staged(
            "silent",
            &manifest("silent"),
            &calling_component(),
            &publisher,
        )
        .await;

    let refusal = home.run(&asking, Some(PERSON)).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_start_failed");
    assert!(
        refusal
            .to_string()
            .contains("the test's bridge handler was reached"),
        "{refusal}"
    );
    let calls = home.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let (capsule_id, person, ceiling) = &calls[0];
    assert_eq!(person.as_deref(), Some(PERSON));
    assert_eq!(
        ceiling.clone().expect("a ceiling while it runs"),
        [
            "elastos://test/bus/probe [read]",
            "localhost://Users/self/Documents/* [read, write]"
        ]
    );
    assert_eq!(home.runtime.ceiling_of(capsule_id), None, "none left after");

    let refusal = home.run(&silent, Some(PERSON)).await.unwrap_err();
    assert!(refusal
        .to_string()
        .ends_with(&format!("BusError::Denied({SEALED_BRIDGE:?})")));
    assert_eq!(
        home.calls().len(),
        1,
        "the sealed capsule reached no handler"
    );
}

/// A-pinned. A pinned bundle that has asks passes its checks and gets
/// nothing by them: it is not started, and its asks do not reach the capsule
/// that pins it. That capsule has no asks of its own, so it is sealed and
/// the handler sees nothing.
#[tokio::test]
async fn a_pinned_bundles_asks_do_not_reach_the_capsule_that_starts() {
    let publisher = key(70);
    let home = Home::trusting(&[&publisher]).await;
    let asks = serde_json::json!([{"resource": "elastos://test/bus/probe", "actions": ["read"]}]);
    let member = manifest_with("asking-member", "asks", asks);
    let member = home
        .staged("asking-member", &member, &calling_component(), &publisher)
        .await;
    let root = manifest_pinning("plain-root", &[("asking-member", &member)]);
    let root = home
        .staged("plain-root", &root, &calling_component(), &publisher)
        .await;

    let refusal = home.run(&root, Some(PERSON)).await.unwrap_err();
    assert!(
        refusal
            .to_string()
            .ends_with(&format!("BusError::Denied({SEALED_BRIDGE:?})")),
        "{refusal}"
    );
    assert_eq!(home.calls(), Vec::new());
}

/// Every Rust file under `dir`.
fn rust_files(dir: &Path, found: &mut Vec<PathBuf>) {
    for item in fs::read_dir(dir).expect("list") {
        let path = item.expect("entry").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The start by CID reads each bundle's slot through the one bounded walk
/// and nothing else, and holds every bundle to one order of checks. A text
/// pin of `run_by_bundle_observed` and of `admit_closure_member`, the one
/// function through which the bundle asked for and each pinned bundle pass.
/// (The walk's name is split below so that the pin on the server's walks,
/// in `stage_cmd`, does not count this file.)
#[test]
fn the_start_by_cid_reads_each_slot_once_and_fetches_nothing() {
    let source = include_str!("runtime.rs");
    let body_of = |signature: &str| {
        let body = &source[source.find(signature).unwrap()..];
        &body[..body.find("\n    }\n").unwrap()]
    };
    let start = body_of("pub(crate) async fn start_by_bundle(");
    let member = body_of("async fn admit_closure_member(");
    let walk = ["checked_bundle", "_within("].concat();
    assert_eq!(start.matches(&walk).count(), 0);
    // One bundle's checks, in their order: the walk; the CID; the signature;
    // and only then the manifest, where a pinned manifest is turned into one
    // that can start, and the component's imports.
    let order = [
        walk.as_str(),
        "after_walk(asked)",
        "bundle.cid() != *asked",
        "bundle_admission::check_bundle_signature(&signature, asked, trust)",
        "bundle_admission::admit_bundle_manifest(",
        "validate_component_imports(",
    ];
    let places: Vec<usize> = order
        .iter()
        .map(|text| {
            assert_eq!(member.matches(text).count(), 1, "{text}");
            member.find(text).unwrap()
        })
        .collect();
    assert!(
        places.windows(2).all(|pair| pair[0] < pair[1]),
        "{places:?}"
    );
    // Who is trusted is read once, by the start, before the first bundle;
    // the member check is handed that reading and takes none of its own;
    // and the reading is let go before anything is loaded.
    let reading = "let trust = self.signature_verifier.read().await;";
    assert_eq!(start.matches(reading).count(), 1);
    assert_eq!(start.matches("signature_verifier").count(), 1);
    assert_eq!(
        start
            .matches(", &trust, &mut left, &mut after_walk)")
            .count(),
        2
    );
    assert!(!member.contains("signature_verifier"));
    assert!(!member.contains("self.check_bundle_signature"));
    let let_go = start.find("drop(trust);").expect("let go");
    assert!(start.find(reading).unwrap() < start.find(".admit_closure_member(").unwrap());
    assert!(start.rfind(".admit_closure_member(").unwrap() < let_go);
    assert!(let_go < start.find("load_admitted").unwrap());
    // The bundle asked for and each pinned one go through that function, and
    // nothing else in the server's code judges a bundle's manifest.
    assert_eq!(start.matches(".admit_closure_member(").count(), 2);
    let production = &source[..source.find("\npub(crate) mod tests {").unwrap()];
    assert_eq!(production.matches(".admit_closure_member(").count(), 2);
    assert_eq!(production.matches("admit_bundle_manifest(").count(), 1);
    // The budget of a start is the server's one walk budget and nothing
    // else: the constant is named once, where the one caller of the observed
    // form hands it over; what is left starts as that budget; and it is
    // changed at two places, each of which only takes away from it.
    assert_eq!(production.matches("BUNDLE_WALK_BUDGET").count(), 1);
    let handed_over = "let budget = bundle_admission::BUNDLE_WALK_BUDGET;\n        \
                       self.run_by_bundle_observed(data_dir, cid, args, principal_id, budget, |_| {})";
    assert_eq!(production.matches(handed_over).count(), 1);
    assert_eq!(production.matches("run_by_bundle_observed(").count(), 2);
    assert_eq!(start.matches("let mut left = budget;").count(), 1);
    assert_eq!(production.matches("&mut left").count(), 2);
    assert_eq!(production.matches("left.max_").count(), 4);
    for shrinks in [
        "left.max_entries = left.max_entries.saturating_sub(files.len());",
        "left.max_total_bytes = left.max_total_bytes.saturating_sub(bytes);",
    ] {
        assert_eq!(member.matches(shrinks).count(), 1, "{shrinks}");
    }
    // No other file of the server calls the observed form but this one.
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let observed = ["run_by_bundle", "_observed("].concat();
    let mut callers: Vec<String> = files
        .iter()
        .filter(|path| fs::read_to_string(path).expect("read").contains(&observed))
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    callers.sort();
    assert_eq!(callers, ["bundle_start_tests.rs", "runtime.rs"]);
    // The start itself is called by the observed form and by the open for a
    // page, and nowhere else; the open hands over the same one budget.
    let start_itself = ["start_by", "_bundle("].concat();
    let mut callers: Vec<String> = files
        .iter()
        .filter(|path| {
            fs::read_to_string(path)
                .expect("read")
                .contains(&start_itself)
        })
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    callers.sort();
    assert_eq!(
        callers,
        ["bundle_start_tests.rs", "page_launch.rs", "runtime.rs"]
    );
    let open = include_str!("page_launch.rs");
    assert_eq!(open.matches(&start_itself).count(), 1);
    assert_eq!(
        open.matches("let budget = crate::bundle_admission::BUNDLE_WALK_BUDGET;")
            .count(),
        1
    );
    for body in [start, member] {
        for never in [
            "fs::read",
            "read_to_string",
            "read_admitted_entrypoint",
            "provider.load(",
            "fetch",
            "resolve_capsule_dir",
            "resource_authority_bounds",
            // It fills no ceiling itself: the shared end does, from the one
            // bounds function.
            "bridge_manifest_capabilities",
            "dev_mode",
            // Nothing is registered as running, and nothing reads the
            // presentation keys: no window, no projection.
            "register_capsule",
            "projections",
            "window_policy",
            "icon",
        ] {
            assert!(!body.contains(never), "{never}");
        }
    }
    // It passes no ceiling of its own: the shared end fills it. One capsule
    // is started, the one asked for.
    assert_eq!(
        start
            .matches("self.start_loaded(component, &mut handle, args, principal_id)")
            .count(),
        1
    );
    // One capsule is loaded, from the walked bytes and the judged manifest:
    // sealed when that manifest has no asks, unsealed when it has. Nothing
    // else decides the seal.
    assert_eq!(
        start
            .matches("let (bytes, manifest) = (starts.component, starts.manifest);")
            .count(),
        1
    );
    let seal = "let loaded = match manifest.asks.is_empty() {\n            \
                true => component.load_admitted_sealed(bytes, manifest).await,\n            \
                false => component.load_admitted(bytes, manifest).await,\n        };";
    assert_eq!(start.matches(seal).count(), 1);
    assert_eq!(start.matches(".load_admitted_sealed(").count(), 1);
    assert_eq!(start.matches(".load_admitted(").count(), 1);
    for never in ["start_loaded", "load_admitted", "provider"] {
        assert!(!member.contains(never), "{never}");
    }
}

/// The pins come off a manifest at one place in the server: where the start
/// by CID judges a bundle's manifest, which the pin above holds to after
/// that bundle's CID and signature checks. The Runtime's reader of pins
/// still hands out no manifest (its own test, in the common crate, is as it
/// was). What comes out is the manifest as the ordinary type reads the same
/// text with every `cid` left out, beside the pins: shown for one pin on the
/// base manifest and for two pins on a manifest that sets every key the
/// start takes, its asks among them. The bundle's own bytes are not
/// changed. (The needle is split so that this file is not counted.)
#[test]
fn the_pins_are_taken_off_a_manifest_at_one_place_and_kept_beside_it() {
    use crate::bundle_admission::admit_bundle_manifest;
    use elastos_bundle_identity::checked_bundle_within as walk;
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&sources, &mut files);
    let taken_off = [".remove(", "\"cid\")"].concat();
    let mut places: Vec<(String, usize)> = files
        .iter()
        .map(|path| {
            let text = fs::read_to_string(path).expect("read");
            let name = path.strip_prefix(&sources).unwrap().to_string_lossy();
            (name.into_owned(), text.matches(&taken_off).count())
        })
        .filter(|(_, count)| *count > 0)
        .collect();
    places.sort();
    // The second is a test of the update controller, which takes the `cid`
    // off a release's descriptor of an external provider: not a manifest,
    // and not a pin.
    assert_eq!(
        places,
        [
            ("bundle_admission.rs".to_string(), 1),
            ("update_controller/tests.rs".to_string(), 1)
        ]
    );

    let dir = tempfile::tempdir().unwrap();
    let pinning = manifest_pinning("pinning", &[("needed", ASKS_NOTHING_CID)]);
    fs::write(dir.path().join("capsule.json"), &pinning).unwrap();
    fs::write(dir.path().join(ENTRYPOINT), quiet_component()).unwrap();
    let walked = walk(dir.path(), BUNDLE_WALK_BUDGET).unwrap();
    let admitted = admit_bundle_manifest(&walked).unwrap();
    assert_eq!(
        admitted.pins,
        [("needed".to_string(), ASKS_NOTHING_CID.to_string())]
    );
    // The expected manifest is the tested text itself, read by the ordinary
    // type once every requirement's `cid` is left out of it.
    let without_the_pins = |text: &str| -> elastos_common::CapsuleManifest {
        let mut value: serde_json::Value = serde_json::from_str(text).unwrap();
        for requirement in value["requires"].as_array_mut().unwrap() {
            let fields = requirement.as_object_mut().unwrap();
            fields.retain(|key, _| key != "cid");
        }
        serde_json::from_value(value).unwrap()
    };
    let same = |admitted: &elastos_common::CapsuleManifest, text: &str| {
        assert_eq!(
            serde_json::to_value(admitted).unwrap(),
            serde_json::to_value(without_the_pins(text)).unwrap()
        );
    };
    same(&admitted.manifest, &pinning);
    assert_eq!(walked.entry("capsule.json").unwrap(), pinning.as_bytes());

    // A manifest with two pins and a value under every key the start takes.
    let other = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
    let mut full: serde_json::Value = serde_json::from_str(&manifest("full")).unwrap();
    let keys = full.as_object_mut().unwrap();
    keys.insert("description".into(), serde_json::json!("every allowed key"));
    keys.insert("author".into(), serde_json::json!("a test"));
    keys.insert("projections".into(), serde_json::json!(["cli", "web"]));
    keys.insert("window_policy".into(), serde_json::json!("multiple"));
    keys.insert("icon".into(), serde_json::json!("icons"));
    keys.insert("resources".into(), serde_json::json!({"memory_mb": 64}));
    keys.insert(
        "requires".into(),
        serde_json::json!([
            {"name": "first", "kind": "capsule", "cid": ASKS_NOTHING_CID},
            {"name": "second", "kind": "capsule", "cid": other}
        ]),
    );
    keys.insert(
        "asks".into(),
        serde_json::json!([{"resource": "elastos://did/*", "actions": ["read"]}]),
    );
    for key in BUNDLE_MANIFEST_KEYS {
        assert!(keys.contains_key(key), "{key} is not set in this row");
    }
    let walk_of = |name: &str, text: &str| {
        let folder = dir.path().join(name);
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("capsule.json"), text).unwrap();
        fs::write(folder.join(ENTRYPOINT), quiet_component()).unwrap();
        walk(&folder, BUNDLE_WALK_BUDGET)
    };
    let text = full.to_string();
    let admitted = admit_bundle_manifest(&walk_of("full", &text).unwrap()).unwrap();
    let pins = [("first", ASKS_NOTHING_CID), ("second", other)];
    assert_eq!(
        admitted.pins,
        pins.map(|(name, cid)| (name.to_string(), cid.to_string()))
    );
    same(&admitted.manifest, &text);

    // The asks came through as they were written, beside the pins.
    assert_eq!(admitted.manifest.asks.len(), 1);
    assert_eq!(admitted.manifest.asks[0].resource, "elastos://did/*");

    // What the conversion never sees: a manifest with a key the manifest
    // type does not know is refused by the walk.
    full["no_such_key"] = serde_json::json!(true);
    let refusal = walk_of("unknown-key", &full.to_string()).unwrap_err();
    assert!(refusal.to_string().contains("no_such_key"), "{refusal}");
}

/// C-walk, the control. A bundle that pins staged bundles starts, and it is
/// the only thing that runs: every pinned bundle here holds the calling
/// component, which, started for its person, calls the bridge and ends in an
/// error. Each pinned bundle is walked once, depth first in the manifests'
/// order (`shared` is pinned twice and checked on its first reach only),
/// each under its own publisher's signature. The capsule that starts is
/// still sealed: a requirement gives it no bridge.
#[tokio::test]
async fn a_bundle_that_pins_staged_bundles_starts_and_only_it_runs() {
    let (publisher, other) = (key(60), key(61));
    let home = Home::trusting(&[&publisher, &other]).await;
    let (quiet, calling) = (quiet_component(), calling_component());
    let shared = home
        .staged("shared", &manifest("shared"), &calling, &other)
        .await;
    let pins_shared = |name: &str| manifest_pinning(name, &[("shared", &shared)]);
    let left = home
        .staged("left", &pins_shared("left"), &calling, &publisher)
        .await;
    let right = home
        .staged("right", &pins_shared("right"), &calling, &other)
        .await;
    let pins_both = |name: &str| manifest_pinning(name, &[("left", &left), ("right", &right)]);
    let root = home
        .staged("root", &pins_both("root"), &quiet, &publisher)
        .await;

    let (ran, walked) = home
        .run_watched(&root, Some(PERSON), BUNDLE_WALK_BUDGET)
        .await;
    assert_eq!(ran.unwrap(), "root");
    assert_eq!(
        walked,
        [
            root.as_str(),
            left.as_str(),
            shared.as_str(),
            right.as_str()
        ]
    );
    assert_eq!(
        home.run(&root, Some(PERSON)).await.unwrap().1,
        did(&publisher.verifying_key()),
        "the signer reported is the one of the bundle asked for"
    );
    assert_eq!(home.calls(), Vec::new());
    assert!(home.runtime.list_capsules().await.is_empty());

    let calling_root = home
        .staged(
            "calling-root",
            &pins_both("calling-root"),
            &calling,
            &publisher,
        )
        .await;
    let refusal = home.run(&calling_root, Some(PERSON)).await.unwrap_err();
    assert_eq!(
        refusal.to_string(),
        format!(
            "bundle_start_failed: Compute error: Component capsule denied: BusError::Denied({SEALED_BRIDGE:?})"
        )
    );
    assert_eq!(home.calls(), Vec::new());
}

/// C-missing. A pin whose bundle the store does not hold refuses the start,
/// under the requirement's name and with the code of a missing bundle.
/// Nothing is fetched and nothing is made in the store.
#[tokio::test]
async fn a_pinned_bundle_that_is_not_in_the_store_refuses_the_start() {
    let publisher = key(62);
    let home = Home::trusting(&[&publisher]).await;
    let absent = "bafybeibc5wcwbtdmjt7qbwbi2rfqvfcfzumivqsoct2ekdqeec2yodqy7q";
    let needs = manifest_pinning("needs", &[("needed", absent)]);
    let root = home
        .staged("needs", &needs, &quiet_component(), &publisher)
        .await;

    let (result, walked) = home.run_watched(&root, None, BUNDLE_WALK_BUDGET).await;
    let refusal = result.unwrap_err();
    assert_eq!(
        refusal,
        under("needed", BundleRefusal::Missing(absent.to_string()))
    );
    assert_eq!(refusal.code(), "bundle_missing");
    assert_eq!(
        refusal.to_string(),
        format!("bundle_missing: this Home's store holds no bundle {absent} (requirement needed)")
    );
    assert_eq!(walked, [root.as_str()]);
    assert!(!bundle_slot(&home.data(), &absent.parse().unwrap()).exists());
}

/// C-member. A pinned bundle is held to every check the bundle asked for is
/// held to, at this start, in the same order. Each row starts from a root
/// that pins one staged bundle signed by another publisher and starts (the
/// control), then changes one thing about the pinned bundle.
#[tokio::test]
async fn a_pinned_bundle_is_held_to_every_check_the_asked_one_is() {
    let (publisher, other) = (key(63), key(64));
    let home = Home::trusting(&[&publisher, &other]).await;
    let quiet = quiet_component();
    // A root named `label` that pins `member` as `needed`.
    let root_pinning = |label: &str, member: &str| {
        let pinning = manifest_pinning(label, &[("needed", member)]);
        (label.to_string(), pinning)
    };
    let needed = manifest("needed");

    // A file of the pinned bundle changed after staging.
    let member = home.staged("changed-needed", &needed, &quiet, &other).await;
    let (label, pinning) = root_pinning("changed", &member);
    let root = home.staged(&label, &pinning, &quiet, &publisher).await;
    assert_eq!(home.run(&root, None).await.unwrap().0, "changed");
    let mut changed = quiet.clone();
    *changed.last_mut().unwrap() ^= 1;
    home.overwrite(&member, ENTRYPOINT, &changed);
    let elsewhere = home.bundle("changed-copy", &needed, &changed);
    let mismatch = BundleRefusal::CidMismatch {
        asked: member.clone(),
        computed: bundle_cid(&elsewhere).unwrap(),
    };
    assert_eq!(
        home.run(&root, None).await.unwrap_err(),
        under("needed", mismatch.clone())
    );
    // The CID is judged before the signature: with the signature gone too,
    // the refusal is still the mismatch.
    let signature = bundle_signature_path(&home.data(), &member.parse().unwrap());
    fs::remove_file(signature).unwrap();
    assert_eq!(
        home.run(&root, None).await.unwrap_err(),
        under("needed", mismatch)
    );

    // Its signature file gone; then its signer no longer trusted, though
    // the root's signer still is.
    let trusted = manifest("trusted");
    let member = home.staged("signed-needed", &trusted, &quiet, &other).await;
    let pinning = manifest_pinning("signed", &[("trusted", &member)]);
    let root = home.staged("signed", &pinning, &quiet, &publisher).await;
    assert_eq!(home.run(&root, None).await.unwrap().0, "signed");
    home.trust(&[&publisher]).await;
    assert_eq!(
        home.run(&root, None).await.unwrap_err(),
        under("trusted", BundleRefusal::SignatureNotAccepted)
    );
    home.trust(&[&publisher, &other]).await;
    assert_eq!(home.run(&root, None).await.unwrap().0, "signed");
    let signature = bundle_signature_path(&home.data(), &member.parse().unwrap());
    fs::remove_file(signature).unwrap();
    assert_eq!(
        home.run(&root, None).await.unwrap_err(),
        under("trusted", BundleRefusal::Unsigned)
    );

    // Its manifest has a key this start does not take: a pinned bundle that
    // declares an authority refuses the start. With its signature gone as
    // well, the refusal is the signature's: a manifest is not judged, and a
    // pinned one not converted, before the signature is accepted.
    let capable = manifest_with(
        "capable",
        "capabilities",
        serde_json::json!(["elastos://did/*"]),
    );
    let member = home.staged("capable", &capable, &quiet, &other).await;
    let pinning = manifest_pinning("wants", &[("capable", &member)]);
    let root = home.staged("wants", &pinning, &quiet, &publisher).await;
    let refusal = home.run(&root, None).await.unwrap_err();
    assert_eq!(
        refusal,
        under(
            "capable",
            BundleRefusal::ManifestFieldRefused("capabilities".to_string())
        )
    );
    assert_eq!(
        refusal.to_string(),
        "bundle_manifest_field_refused: capabilities (requirement capable)"
    );
    let signature = bundle_signature_path(&home.data(), &member.parse().unwrap());
    fs::remove_file(signature).unwrap();
    assert_eq!(
        home.run(&root, None).await.unwrap_err(),
        under("capable", BundleRefusal::Unsigned)
    );

    // It is not an app component of the contract: by its role, and by what
    // its component imports.
    let viewer = manifest_with("a-viewer", "role", serde_json::json!("viewer"));
    let member = home.staged("a-viewer", &viewer, &quiet, &other).await;
    let pinning = manifest_pinning("shows", &[("a-viewer", &member)]);
    let root = home.staged("shows", &pinning, &quiet, &publisher).await;
    let refusal = home.run(&root, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_not_a_component");
    assert!(matches!(&refusal, BundleRefusal::Requirement { name, .. } if name == "a-viewer"));
    let member = home
        .staged(
            "imports",
            &manifest("imports"),
            &component_with_extra_import(),
            &other,
        )
        .await;
    let pinning = manifest_pinning("links", &[("imports", &member)]);
    let root = home.staged("links", &pinning, &quiet, &publisher).await;
    let refusal = home.run(&root, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_not_a_component");
    assert!(refusal.to_string().contains("wasi:filesystem"), "{refusal}");
    assert!(refusal.to_string().ends_with("(requirement imports)"));
    assert_eq!(home.calls(), Vec::new());
}

/// C-name. The bundle staged under a pin must be called what the
/// requirement that pins it is called. The control pins the same bundle
/// under its own name.
#[tokio::test]
async fn the_bundle_under_a_pin_carries_the_requirements_name() {
    let publisher = key(65);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = quiet_component();
    let member = home
        .staged("other", &manifest("other"), &quiet, &publisher)
        .await;
    let wrong = manifest_pinning("wrong", &[("needed", &member)]);
    let wrong = home.staged("wrong", &wrong, &quiet, &publisher).await;
    let refusal = home.run(&wrong, None).await.unwrap_err();
    assert_eq!(
        refusal,
        under(
            "needed",
            BundleRefusal::RequirementMismatch("other".to_string())
        )
    );
    assert_eq!(
        refusal.to_string(),
        "bundle_requirement_mismatch: the bundle staged under the pin is called \"other\" (requirement needed)"
    );

    let right = manifest_pinning("right", &[("other", &member)]);
    let right = home.staged("right", &right, &quiet, &publisher).await;
    assert_eq!(home.run(&right, None).await.unwrap().0, "right");
}

/// C-unpinned, C-names. A requirement without a pin refuses the start, also
/// beside one that has a pin, and so does a requirement whose name is not
/// plain; in both cases before any pinned bundle is looked at. The same
/// holds for the manifest of a pinned bundle. The control has a pin and a
/// name that uses every kind of plain character.
#[tokio::test]
async fn a_requirement_without_a_pin_or_with_an_odd_name_refuses_the_start() {
    let publisher = key(66);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = quiet_component();
    let plain = "a.B_c-1";
    let member = home
        .staged("plain", &manifest(plain), &quiet, &publisher)
        .await;
    let control = manifest_pinning("control", &[(plain, &member)]);
    let control = home.staged("control", &control, &quiet, &publisher).await;
    assert_eq!(home.run(&control, None).await.unwrap().0, "control");

    let loose = serde_json::json!({"name": "loose", "kind": "capsule"});
    let pinned = serde_json::json!({"name": plain, "kind": "capsule", "cid": member});
    let rows = [
        ("alone", serde_json::json!([loose])),
        ("after", serde_json::json!([pinned, loose])),
        ("before", serde_json::json!([loose, pinned])),
    ];
    for (name, requires) in rows {
        let unpinned = manifest_with(name, "requires", requires);
        let root = home.staged(name, &unpinned, &quiet, &publisher).await;
        let (result, walked) = home.run_watched(&root, None, BUNDLE_WALK_BUDGET).await;
        let refusal = result.unwrap_err();
        assert_eq!(
            refusal,
            BundleRefusal::RequirementUnpinned("loose".to_string()),
            "{name}"
        );
        assert_eq!(refusal.to_string(), "bundle_requirement_unpinned: loose");
        assert_eq!(walked, [root.as_str()], "{name}");
    }

    for (row, odd) in ["a/b", "a*", "..", ".", "a b", "a\\b"]
        .into_iter()
        .enumerate()
    {
        let name = format!("odd-{row}");
        let root = manifest_pinning(&name, &[(odd, &member)]);
        let root = home.staged(&name, &root, &quiet, &publisher).await;
        let (result, walked) = home.run_watched(&root, None, BUNDLE_WALK_BUDGET).await;
        let refusal = result.unwrap_err();
        assert_eq!(
            refusal,
            BundleRefusal::RequirementNameInvalid(odd.to_string()),
            "{odd}"
        );
        assert_eq!(refusal.code(), "bundle_requirement_name_invalid");
        assert_eq!(walked, [root.as_str()], "{odd}");
    }

    // A pinned bundle's own manifest is held to the same rule.
    let inner = manifest_with("inner", "requires", serde_json::json!([loose]));
    let inner = home.staged("inner", &inner, &quiet, &publisher).await;
    let outer = manifest_pinning("outer", &[("inner", &inner)]);
    let outer = home.staged("outer", &outer, &quiet, &publisher).await;
    assert_eq!(
        home.run(&outer, None).await.unwrap_err(),
        under(
            "inner",
            BundleRefusal::RequirementUnpinned("loose".to_string())
        )
    );
}

/// C-budget. The bundles of one start share one budget of bytes and of
/// files: the bundle asked for counts, and so does each pinned bundle. With
/// exactly what the three bundles here hold, the start goes ahead; with one
/// byte less, or one file less, the walk of the last bundle is refused, and
/// that bundle alone starts under the same budget.
#[tokio::test]
async fn the_bundles_of_one_start_share_one_budget() {
    let publisher = key(67);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = quiet_component();
    let bytes = |manifest: &str| (manifest.len() + quiet.len()) as u64;
    let (first, second) = (manifest("first"), manifest("second"));
    let first_cid = home.staged("first", &first, &quiet, &publisher).await;
    let second_cid = home.staged("second", &second, &quiet, &publisher).await;
    let root = manifest_pinning("root", &[("first", &first_cid), ("second", &second_cid)]);
    let root_cid = home.staged("root", &root, &quiet, &publisher).await;

    // Three bundles of two files each.
    let exact = Budget {
        max_entries: 6,
        max_total_bytes: bytes(&root) + bytes(&first) + bytes(&second),
        ..BUNDLE_WALK_BUDGET
    };
    let (ran, walked) = home.run_watched(&root_cid, None, exact).await;
    assert_eq!(ran.unwrap(), "root");
    assert_eq!(
        walked,
        [root_cid.as_str(), first_cid.as_str(), second_cid.as_str()]
    );

    let a_byte_less = Budget {
        max_total_bytes: exact.max_total_bytes - 1,
        ..exact
    };
    let a_file_less = Budget {
        max_entries: 5,
        ..exact
    };
    for (short, limit) in [(a_byte_less, "total bytes"), (a_file_less, "entries")] {
        let (result, walked) = home.run_watched(&root_cid, None, short).await;
        let refusal = result.unwrap_err();
        assert_eq!(refusal.code(), "bundle_walk_over_budget", "{refusal}");
        assert!(
            matches!(&refusal, BundleRefusal::Requirement { name, .. } if name == "second"),
            "{refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains(&format!("the walk's limit on {limit}")),
            "{refusal}"
        );
        assert_eq!(walked, [root_cid.as_str(), first_cid.as_str()], "{limit}");
        let (alone, _) = home.run_watched(&second_cid, None, short).await;
        assert_eq!(alone.unwrap(), "second");
    }
}

/// C-limits. A pin may sit at depth 4 and not at depth 5, the bundle asked
/// for being depth 1; and one start takes in 16 bundles and not 17. The
/// bundle past either limit is not read.
#[tokio::test]
async fn a_closure_is_limited_in_depth_and_in_number() {
    let publisher = key(68);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = quiet_component();

    // n1 pins n2, which pins n3, and so on down to n5.
    let mut chain = vec![home.staged("n5", &manifest("n5"), &quiet, &publisher).await];
    for level in (1..5).rev() {
        let (name, below) = (format!("n{level}"), format!("n{}", level + 1));
        let pinning = manifest_pinning(&name, &[(&below, chain.last().unwrap())]);
        chain.push(home.staged(&name, &pinning, &quiet, &publisher).await);
    }
    chain.reverse();
    let (ran, walked) = home.run_watched(&chain[1], None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(ran.unwrap(), "n2");
    assert_eq!(walked, chain[1..]);
    let (result, walked) = home.run_watched(&chain[0], None, BUNDLE_WALK_BUDGET).await;
    let refusal = result.unwrap_err();
    assert_eq!(refusal, under("n5", BundleRefusal::ClosureTooDeep));
    assert_eq!(
        refusal.to_string(),
        "bundle_closure_too_deep: a pin sits below depth 4 (requirement n5)"
    );
    assert_eq!(walked, chain[..4]);

    let mut leaves = Vec::new();
    for leaf in 1..=16 {
        let name = format!("m{leaf}");
        let cid = home
            .staged(&name, &manifest(&name), &quiet, &publisher)
            .await;
        leaves.push((name, cid));
    }
    let pins: Vec<(&str, &str)> = leaves
        .iter()
        .map(|(name, cid)| (name.as_str(), cid.as_str()))
        .collect();
    let sixteen = manifest_pinning("sixteen", &pins[..15]);
    let sixteen = home.staged("sixteen", &sixteen, &quiet, &publisher).await;
    let (ran, walked) = home.run_watched(&sixteen, None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(ran.unwrap(), "sixteen");
    assert_eq!(walked.len(), 16);
    let seventeen = manifest_pinning("seventeen", &pins);
    let seventeen = home
        .staged("seventeen", &seventeen, &quiet, &publisher)
        .await;
    let (result, walked) = home.run_watched(&seventeen, None, BUNDLE_WALK_BUDGET).await;
    let refusal = result.unwrap_err();
    assert_eq!(refusal, under("m16", BundleRefusal::ClosureTooMany));
    assert_eq!(
        refusal.to_string(),
        "bundle_closure_too_many: more than 16 bundles (requirement m16)"
    );
    assert_eq!(walked.len(), 16);
    assert!(!walked.contains(&leaves[15].1));
}

/// C-diamond. A bundle that two pins reach is admitted on its first reach and
/// only there: it is walked once, taken off the shared budget once and
/// counted once, so a closure that fits its limits exactly still fits when
/// one of its bundles is reached twice. On the second reach the one thing
/// compared is the name: a requirement that calls the bundle something else
/// than it is called is refused, and nothing is read for that. The depth
/// limit is the one limit that still holds there: no pin sits below it.
#[tokio::test]
async fn a_bundle_two_pins_reach_is_checked_and_counted_once() {
    let publisher = key(70);
    let home = Home::trusting(&[&publisher]).await;
    let quiet = quiet_component();
    let bytes = |manifest: &str| (manifest.len() + quiet.len()) as u64;
    let shared = manifest("shared");
    let shared_cid = home.staged("shared", &shared, &quiet, &publisher).await;
    let left = manifest_pinning("left", &[("shared", &shared_cid)]);
    let left_cid = home.staged("left", &left, &quiet, &publisher).await;
    let right = manifest_pinning("right", &[("shared", &shared_cid)]);
    let right_cid = home.staged("right", &right, &quiet, &publisher).await;
    let root = manifest_pinning("root", &[("left", &left_cid), ("right", &right_cid)]);
    let root_cid = home.staged("root", &root, &quiet, &publisher).await;

    // Four bundles of two files each; the shared one's bytes once.
    let exact = Budget {
        max_entries: 8,
        max_total_bytes: bytes(&root) + bytes(&left) + bytes(&right) + bytes(&shared),
        ..BUNDLE_WALK_BUDGET
    };
    let (ran, walked) = home.run_watched(&root_cid, None, exact).await;
    assert_eq!(ran.unwrap(), "root");
    let once = [&root_cid, &left_cid, &shared_cid, &right_cid];
    assert_eq!(walked.iter().collect::<Vec<_>>(), once);
    // The control: that budget is exact. A byte or a file less and the last
    // bundle walked, the one under `right`, no longer fits.
    for short in [
        Budget {
            max_total_bytes: exact.max_total_bytes - 1,
            ..exact
        },
        Budget {
            max_entries: 7,
            ..exact
        },
    ] {
        let (result, walked) = home.run_watched(&root_cid, None, short).await;
        let refusal = result.unwrap_err();
        assert_eq!(refusal.code(), "bundle_walk_over_budget", "{refusal}");
        assert!(
            matches!(&refusal, BundleRefusal::Requirement { name, .. } if name == "right"),
            "{refusal}"
        );
        assert_eq!(walked.iter().collect::<Vec<_>>(), once[..3]);
    }

    // Counted once: sixteen different bundles, one of them reached through
    // two pins, are sixteen and start.
    let mut pins = vec![
        ("left".to_string(), left_cid.clone()),
        ("right".to_string(), right_cid.clone()),
    ];
    for leaf in 1..=12 {
        let name = format!("d{leaf}");
        let cid = home
            .staged(&name, &manifest(&name), &quiet, &publisher)
            .await;
        pins.push((name, cid));
    }
    let pins: Vec<(&str, &str)> = pins
        .iter()
        .map(|(name, cid)| (name.as_str(), cid.as_str()))
        .collect();
    let sixteen = manifest_pinning("sixteen-with-a-diamond", &pins);
    let sixteen = home.staged("sixteen", &sixteen, &quiet, &publisher).await;
    let (ran, walked) = home.run_watched(&sixteen, None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(ran.unwrap(), "sixteen-with-a-diamond");
    assert_eq!(walked.len(), 16);
    assert_eq!(walked.iter().filter(|cid| **cid == shared_cid).count(), 1);

    // The second reach under another name. `left` reaches the shared bundle
    // first, as `shared`; the root then pins the same bundle as `alias`.
    let alias = manifest_pinning("alias-root", &[("left", &left_cid), ("alias", &shared_cid)]);
    let alias = home.staged("alias-root", &alias, &quiet, &publisher).await;
    let (result, walked) = home.run_watched(&alias, None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(
        result.unwrap_err(),
        under("alias", BundleRefusal::RequirementMismatch("shared".into()))
    );
    assert_eq!(
        walked.iter().collect::<Vec<_>>(),
        [&alias, &left_cid, &shared_cid]
    );

    // The depth limit holds for a second reach too. `shared` is first
    // reached at depth 2. `c` pins it again: with `c` at depth 3 that pin
    // sits at depth 4 and the start goes ahead; with `c` at depth 4 it sits
    // at depth 5 and is refused, though nothing would be read for it.
    let c = manifest_pinning("c", &[("shared", &shared_cid)]);
    let c = home.staged("c", &c, &quiet, &publisher).await;
    let b = manifest_pinning("b", &[("c", &c)]);
    let b = home.staged("b", &b, &quiet, &publisher).await;
    let a = manifest_pinning("a", &[("b", &b)]);
    let a = home.staged("a", &a, &quiet, &publisher).await;
    let at_four = manifest_pinning("at-four", &[("shared", &shared_cid), ("b", &b)]);
    let at_four = home.staged("at-four", &at_four, &quiet, &publisher).await;
    let (ran, walked) = home.run_watched(&at_four, None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(ran.unwrap(), "at-four");
    assert_eq!(
        walked.iter().collect::<Vec<_>>(),
        [&at_four, &shared_cid, &b, &c]
    );
    let at_five = manifest_pinning("at-five", &[("shared", &shared_cid), ("a", &a)]);
    let at_five = home.staged("at-five", &at_five, &quiet, &publisher).await;
    let (result, walked) = home.run_watched(&at_five, None, BUNDLE_WALK_BUDGET).await;
    assert_eq!(
        result.unwrap_err(),
        under("shared", BundleRefusal::ClosureTooDeep)
    );
    assert_eq!(
        walked.iter().collect::<Vec<_>>(),
        [&at_five, &shared_cid, &a, &b, &c]
    );
    // The answer does not turn on the order of the root's requirements. With
    // the long way first, the pin at depth 5 is the first reach of `shared`,
    // and it is refused the same.
    let long_first = manifest_pinning("long-first", &[("a", &a), ("shared", &shared_cid)]);
    let long_first = home
        .staged("long-first", &long_first, &quiet, &publisher)
        .await;
    let (result, walked) = home
        .run_watched(&long_first, None, BUNDLE_WALK_BUDGET)
        .await;
    assert_eq!(
        result.unwrap_err(),
        under("shared", BundleRefusal::ClosureTooDeep)
    );
    assert_eq!(walked.iter().collect::<Vec<_>>(), [&long_first, &a, &b, &c]);

    // Nor does it turn on the order when the shared bundle has bundles below
    // it. `over` pins `under`, which pins `below`. A root pins `over` and
    // `via`, and `via` pins `over` again, one level down. Reached the short
    // way first, `over` sits at depth 2 and `below` at depth 4; the second
    // reach puts `over` at depth 3, and so `below` at depth 5, which is
    // measured then, out of memory, and refused. Reached the long way first,
    // `below` is met at depth 5 at once. The same refusal either way; and
    // with one level less below the shared bundle, a start either way.
    for (levels, refused) in [(2, true), (1, false)] {
        let named = |part: &str| format!("{part}-{levels}");
        let below = manifest(&named("below"));
        let mut lowest = home
            .staged(&named("below"), &below, &quiet, &publisher)
            .await;
        let mut lowest_name = named("below");
        if levels == 2 {
            let under = manifest_pinning(&named("under"), &[(&lowest_name, &lowest)]);
            lowest = home
                .staged(&named("under"), &under, &quiet, &publisher)
                .await;
            lowest_name = named("under");
        }
        let over = manifest_pinning(&named("over"), &[(&lowest_name, &lowest)]);
        let over = home.staged(&named("over"), &over, &quiet, &publisher).await;
        let via = manifest_pinning(&named("via"), &[(&named("over"), &over)]);
        let via = home.staged(&named("via"), &via, &quiet, &publisher).await;
        let (over_pin, via_pin) = ((named("over"), over), (named("via"), via));
        let orders = [
            ("short-first", [&over_pin, &via_pin]),
            ("long-first", [&via_pin, &over_pin]),
        ];
        for (order, pins) in orders {
            let pins: Vec<(&str, &str)> = pins
                .iter()
                .map(|(name, cid)| (name.as_str(), cid.as_str()))
                .collect();
            let name = format!("{order}-{levels}");
            let root = manifest_pinning(&name, &pins);
            let root = home.staged(&name, &root, &quiet, &publisher).await;
            let (result, walked) = home.run_watched(&root, None, BUNDLE_WALK_BUDGET).await;
            match refused {
                true => assert_eq!(
                    result.unwrap_err(),
                    under(&named("below"), BundleRefusal::ClosureTooDeep),
                    "{order}"
                ),
                false => assert_eq!(result.unwrap(), name, "{order}"),
            }
            // Measuring again reads nothing: every bundle is walked once at
            // most, the shared one and what is below it included, and the
            // bundle refused for its depth the long way round is not read.
            let mut once = walked.clone();
            once.sort();
            once.dedup();
            assert_eq!(once.len(), walked.len(), "{order}: {walked:?}");
            let unread = usize::from(refused && order == "long-first");
            assert_eq!(walked.len(), levels + 3 - unread, "{order}: {walked:?}");
        }
    }
}

/// C-trust. One reading of who is trusted judges every bundle of a start.
/// While the start walks its bundles, the bundle asked for and each pinned
/// one, trust cannot be replaced; before the start, after it, after a start
/// that was refused, and while the started capsule runs, it can.
#[tokio::test]
async fn one_reading_of_trust_judges_every_bundle_of_a_start() {
    let publisher = key(71);
    let home = Home::trusting(&[&publisher]).await;
    let asks = serde_json::json!([{"resource": "elastos://test/bus/probe", "actions": ["read"]}]);
    let first = home
        .staged("first", &manifest("first"), &quiet_component(), &publisher)
        .await;
    let second = home
        .staged(
            "second",
            &manifest("second"),
            &quiet_component(),
            &publisher,
        )
        .await;
    let mut root: serde_json::Value = serde_json::from_str(&manifest_pinning(
        "root",
        &[("first", &first), ("second", &second)],
    ))
    .unwrap();
    root["asks"] = asks;
    let root = home
        .staged("root", &root.to_string(), &calling_component(), &publisher)
        .await;

    // While the capsule runs: asked from inside the Home's bridge handler,
    // which the calling component reaches because its manifest has asks.
    let (during_run, runtime) = (
        Arc::new(Mutex::new(Vec::new())),
        Arc::downgrade(&home.runtime),
    );
    let seen = during_run.clone();
    home.runtime
        .set_bridge_hostcall(Arc::new(move |_line, _capsule, _principal| {
            let free = runtime.upgrade().map(|it| it.trust_can_change_now());
            seen.lock().unwrap().push(free);
            Err("the test's bridge handler was reached".to_string())
        }));

    assert!(home.runtime.trust_can_change_now());
    let mut during_walks = Vec::new();
    let person = Some(PERSON.to_string());
    let result = home
        .runtime
        .run_by_bundle_observed(
            &home.data(),
            &root,
            Vec::new(),
            person,
            BUNDLE_WALK_BUDGET,
            |_| during_walks.push(home.runtime.trust_can_change_now()),
        )
        .await;
    // The component's one call was refused by the test's handler, so the
    // start ends in that error: everything before it passed.
    assert_eq!(result.unwrap_err().code(), "bundle_start_failed");
    assert_eq!(during_walks, [false, false, false]);
    assert_eq!(*during_run.lock().unwrap(), [Some(true)]);
    assert!(home.runtime.trust_can_change_now());

    // A start that is refused part-way lets its reading go too.
    let missing = manifest_pinning("lonely", &[("gone", crate::bundle_admission::tests::CID_A)]);
    let missing = home
        .staged("lonely", &missing, &quiet_component(), &publisher)
        .await;
    assert_eq!(code(home.run(&missing, None).await), "bundle_missing");
    assert!(home.runtime.trust_can_change_now());
}

/// C-external. A requirement of kind `external` names a host dependency,
/// not a bundle. The manifest type refuses one on an app capsule, and a start
/// by CID takes only app components: so no bundle that starts by CID has one,
/// and this start needs no rule for who serves it. Staging refuses such a
/// bundle, so the slot is written here by hand.
#[tokio::test]
async fn an_external_requirement_is_refused_at_a_start_by_cid() {
    let publisher = key(72);
    let home = Home::trusting(&[&publisher]).await;
    let folder = home.bundle("plain", &manifest("plain"), &quiet_component());
    let cid = home.stage(&folder, &publisher).await;
    let external = serde_json::json!([{"name": "did-provider", "kind": "external"}]);
    let external = manifest_with("plain", "requires", external);
    home.overwrite(&cid, "capsule.json", external.as_bytes());
    let refusal = home.run(&cid, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_walk_manifest_invalid");
    assert!(
        refusal
            .to_string()
            .contains("app capsules cannot require external host dependencies"),
        "{refusal}"
    );
}

/// A-wide. An ask that covers a whole scheme is refused at a start by CID,
/// however it is spelled; an ask that names something under its scheme is
/// taken. Judged as the bridge reads a pattern, so the spellings the bridge
/// would fold into `scheme://*` are refused with it.
#[tokio::test]
async fn an_ask_that_covers_a_whole_scheme_is_refused_at_a_start_by_cid() {
    let publisher = key(73);
    let home = Home::trusting(&[&publisher]).await;
    let asking = |resource: &str| {
        let asks = serde_json::json!([
            {"resource": "elastos://test/bus/probe", "actions": ["read"]},
            {"resource": resource, "actions": ["read"]}
        ]);
        manifest_with("asking", "asks", asks)
    };
    for wide in [
        "elastos://*",
        "elastos:///*",
        "elastos://./*",
        "localhost://*",
    ] {
        let cid = home
            .staged("wide", &asking(wide), &quiet_component(), &publisher)
            .await;
        let refusal = home.run(&cid, None).await.unwrap_err();
        assert_eq!(refusal, BundleRefusal::AskTooWide(wide.into()), "{wide}");
        assert_eq!(
            refusal.to_string(),
            format!("bundle_ask_too_wide: the ask for {wide:?} covers a whole scheme")
        );
    }
    for named in [
        "elastos://did/*",
        "elastos://a",
        "elastos://launch/content/*",
        "localhost://Users/self/Documents/*",
    ] {
        let cid = home
            .staged("named", &asking(named), &quiet_component(), &publisher)
            .await;
        assert_eq!(home.run(&cid, None).await.unwrap().0, "asking", "{named}");
    }
}

/// C-fresh. A start by CID never hands the start to a capsule that is
/// already there: two starts of one CID are two instances, each under an id
/// of its own.
#[tokio::test]
async fn two_starts_of_one_cid_are_two_instances() {
    let publisher = key(74);
    let home = Home::trusting(&[&publisher]).await;
    let cid = home
        .staged("twice", &manifest("twice"), &quiet_component(), &publisher)
        .await;
    let data = home.data();
    let start = || home.runtime.run_by_bundle(&data, &cid, Vec::new(), None);
    let (first, _) = start().await.unwrap();
    let (second, _) = start().await.unwrap();
    assert_ne!(first.id.0, second.id.0);
}

/// A content manifest that pins `pins`, and a page manifest that pins `pins`:
/// each with the one file `ENTRYPOINT` as its entrypoint, which for them is
/// bytes to show and never code.
fn content_manifest(name: &str, pins: &[(&str, &str)]) -> serde_json::Value {
    let pin = |(name, cid): &(&str, &str)| serde_json::json!({"name": name, "kind": "capsule", "cid": cid});
    serde_json::json!({
        "schema": "elastos.capsule/v1", "name": name, "version": "0.1.0",
        "role": "content", "type": "data", "entrypoint": ENTRYPOINT,
        "requires": pins.iter().map(pin).collect::<Vec<_>>()
    })
}

fn page_manifest(name: &str, pins: &[(&str, &str)]) -> serde_json::Value {
    let mut page = content_manifest(name, pins);
    for (key, value) in [
        ("role", "viewer"),
        ("type", "wasm"),
        ("runtime_abi", "elastos.runtime-projection/v1"),
        ("bus_contract", "elastos.runtime-projection/v1"),
        ("execution", "web-projection"),
    ] {
        page[key] = value.into();
    }
    page["projections"] = serde_json::json!(["web"]);
    page
}

/// K-launch. Content named by its CID starts its viewer's one program. The
/// content pins a page, the page pins a program, its core; each is staged
/// under a publisher of its own and walked once, in that order; the core is
/// what runs, under its own asks, and the content and the page get no
/// instance. The signer reported is the content's. A core without asks is
/// sealed there as anywhere. A program the core pins is checked like any
/// pinned program.
#[tokio::test]
async fn content_named_by_cid_starts_its_viewers_one_program() {
    let (of_content, of_page, of_core) = (key(80), key(81), key(82));
    let home = Home::trusting(&[&of_content, &of_page, &of_core]).await;
    let picture = b"not code: the bytes of a picture".to_vec();
    let asks = serde_json::json!([{"resource": "elastos://test/bus/probe", "actions": ["read"]}]);
    let helper = home
        .staged("helper", &manifest("helper"), &quiet_component(), &of_core)
        .await;
    let mut core: serde_json::Value =
        serde_json::from_str(&manifest_pinning("core", &[("helper", &helper)])).unwrap();
    core["asks"] = asks;
    let core = home
        .staged("core", &core.to_string(), &calling_component(), &of_core)
        .await;
    let page = page_manifest("page", &[("core", &core)]).to_string();
    let page = home.staged("page", &page, &picture, &of_page).await;
    let content = content_manifest("pictures", &[("page", &page)]).to_string();
    let content = home
        .staged("pictures", &content, &picture, &of_content)
        .await;

    let (ran, walked) = home
        .run_watched(&content, Some(PERSON), BUNDLE_WALK_BUDGET)
        .await;
    // The core ran and made its one call, which this Home's handler refuses.
    assert_eq!(ran.unwrap_err().code(), "bundle_start_failed");
    assert_eq!(
        walked.iter().collect::<Vec<_>>(),
        [&content, &page, &core, &helper]
    );
    let calls = home.calls();
    assert_eq!(calls.len(), 1, "one instance ran, and it called once");
    assert_eq!(calls[0].1.as_deref(), Some(PERSON));
    assert_eq!(
        calls[0].2,
        Some(vec!["elastos://test/bus/probe [read]".to_string()]),
        "the core runs under its own asks"
    );
    assert!(home.runtime.list_capsules().await.is_empty());

    // The same closure with a quiet core that asks for nothing: it starts,
    // sealed, and ends well; what is reported is the core's name and the
    // content's signer.
    let quiet = home
        .staged("core", &manifest("core"), &quiet_component(), &of_core)
        .await;
    let page = page_manifest("page", &[("core", &quiet)]).to_string();
    let page = home.staged("page", &page, &picture, &of_page).await;
    let content = content_manifest("pictures", &[("page", &page)]).to_string();
    let content = home
        .staged("pictures", &content, &picture, &of_content)
        .await;
    assert_eq!(
        home.run(&content, Some(PERSON)).await.unwrap(),
        ("core".to_string(), did(&of_content.verifying_key()))
    );
    assert_eq!(home.calls().len(), 1, "no further call");

    // Each of the three is held to its own publisher: with one of the three
    // keys no longer trusted, the bundle that key signed is refused, under
    // its requirement's name when it is a pinned one.
    for (trusted, refused_under) in [
        ([&of_page, &of_core], None),
        ([&of_content, &of_core], Some("page")),
        ([&of_content, &of_page], Some("core")),
    ] {
        home.trust(&trusted).await;
        let refusal = home.run(&content, None).await.unwrap_err();
        assert_eq!(refusal.code(), "bundle_signature_not_accepted", "{refusal}");
        match (&refusal, refused_under) {
            (BundleRefusal::Requirement { name, .. }, Some(under)) => assert_eq!(name, under),
            (BundleRefusal::Requirement { .. }, None) => panic!("{refusal}"),
            (_, under) => assert_eq!(under, None, "{refusal}"),
        }
    }
    home.trust(&[&of_content, &of_page, &of_core]).await;

    // A wrong CID at any of the three: one byte of the staged file changed.
    for (cid, under_name) in [
        (&content, None),
        (&page, Some("page")),
        (&quiet, Some("core")),
    ] {
        let before = fs::read(home.slot_file(cid, ENTRYPOINT)).unwrap();
        let mut changed = before.clone();
        changed.push(b'x');
        home.overwrite(cid, ENTRYPOINT, &changed);
        let refusal = home.run(&content, None).await.unwrap_err();
        assert_eq!(refusal.code(), "bundle_cid_mismatch", "{refusal}");
        let named = matches!(&refusal, BundleRefusal::Requirement { name, .. } if Some(name.as_str()) == under_name);
        assert_eq!(named, under_name.is_some(), "{refusal}");
        home.overwrite(cid, ENTRYPOINT, &before);
    }
    assert_eq!(home.run(&content, None).await.unwrap().0, "core");
}

/// K-places. Each kind has its places and no other. Content pins exactly
/// one bundle and that is a page; a page pins exactly one bundle and that is
/// a program; a page is not started by its own CID; under a program only
/// programs sit (content pinned by a program is a shape this start does not
/// take). Content is passive, an ask included; a page asks for nothing and
/// holds no key outside the list.
#[tokio::test]
async fn each_kind_of_bundle_has_its_places_and_no_other() {
    let publisher = key(83);
    let home = Home::trusting(&[&publisher]).await;
    let (quiet, bytes) = (quiet_component(), b"bytes to show".to_vec());
    let program = home
        .staged("core", &manifest("core"), &quiet, &publisher)
        .await;
    let other = home
        .staged("other", &manifest("other"), &quiet, &publisher)
        .await;
    let staged = |name: &'static str, manifest: serde_json::Value| {
        let (home, bytes, publisher) = (&home, &bytes, &publisher);
        async move {
            home.staged(name, &manifest.to_string(), bytes, publisher)
                .await
        }
    };
    let page = staged("page", page_manifest("page", &[("core", &program)])).await;
    let content = staged("pictures", content_manifest("pictures", &[("page", &page)])).await;
    assert_eq!(home.run(&content, None).await.unwrap().0, "core");

    // Content: exactly one pin, refused before anything below it is read.
    for (pins, count) in [
        (vec![], 0),
        (vec![("page", page.as_str()), ("core", program.as_str())], 2),
    ] {
        let cid = staged("lonely", content_manifest("lonely", &pins)).await;
        let (result, walked) = home.run_watched(&cid, None, BUNDLE_WALK_BUDGET).await;
        assert_eq!(
            result.unwrap_err(),
            BundleRefusal::ContentRequiresInvalid(count)
        );
        assert_eq!(walked, [cid.as_str()]);
    }
    // Content: what it pins is a page.
    for (name, pinned, found) in [
        ("core", &program, "a program"),
        ("pictures", &content, "content"),
    ] {
        let cid = staged("odd", content_manifest("odd", &[(name, pinned)])).await;
        assert_eq!(
            home.run(&cid, None).await.unwrap_err().to_string(),
            format!("bundle_member_kind_refused: {found} is pinned where a page must be (requirement {name})")
        );
    }
    // Content is passive.
    let ask = serde_json::json!([{"resource": "elastos://did/*", "actions": ["read"]}]);
    for (key, value, field) in [
        ("asks", ask.clone(), "asks"),
        ("execution", serde_json::json!("data"), "execution"),
    ] {
        let mut active = content_manifest("active", &[("page", &page)]);
        active[key] = value;
        let cid = staged("active", active).await;
        assert_eq!(
            home.run(&cid, None).await.unwrap_err(),
            BundleRefusal::ContentNotPassive(field.into()),
            "{key}"
        );
    }

    // A page: not by its own CID.
    assert_eq!(
        home.run(&page, None).await.unwrap_err().to_string(),
        "bundle_member_kind_refused: a page is not started by its own CID"
    );
    // A page: exactly one pin, and it is a program.
    let over = |page: String| {
        let (home, staged) = (&home, &staged);
        async move {
            let cid = staged("over", content_manifest("over", &[("page", &page)])).await;
            home.run(&cid, None).await.unwrap_err().to_string()
        }
    };
    for (pins, count) in [
        (vec![], 0),
        (
            vec![("core", program.as_str()), ("other", other.as_str())],
            2,
        ),
    ] {
        let page = staged("page", page_manifest("page", &pins)).await;
        assert_eq!(
            over(page).await,
            format!("bundle_viewer_core_invalid: the viewer pins {count} bundles, not its one program (requirement page)")
        );
    }
    for (name, pinned, found) in [("pictures", &content, "content"), ("page", &page, "a page")] {
        let outer = staged("page", page_manifest("page", &[(name, pinned)])).await;
        let refusal = over(outer).await;
        let expected = format!("bundle_viewer_core_invalid: the viewer pins {found}, not a program (requirement {name})");
        assert!(refusal.starts_with(&expected), "{refusal}");
    }
    // A page: no asks, and no key outside the list.
    let interface = serde_json::json!([{
        "id": "elastos.photos.viewer", "version": "0.1.0",
        "methods": [{
            "id": "playlist.show", "description": "show", "risk": "read",
            "approval": "runtime_policy", "audit": "event", "operation": "show",
            "resource": "localhost://Users/self/.AppData/App/photo-viewer/playlist.json"
        }]
    }]);
    for (key, value) in [("asks", ask), ("interfaces", interface)] {
        let mut asking = page_manifest("page", &[("core", &program)]);
        asking[key] = value;
        let refusal = over(staged("page", asking).await).await;
        assert_eq!(
            refusal,
            format!("bundle_manifest_field_refused: {key} (requirement page)")
        );
    }

    // Under a program only programs sit. Content pinned by a program is a
    // shape this start does not take; so is a page.
    for (name, pinned, found) in [("pictures", &content, "content"), ("page", &page, "a page")] {
        let root = manifest_pinning("root", &[(name, pinned)]);
        let cid = home.staged("root", &root, &quiet, &publisher).await;
        assert_eq!(
            home.run(&cid, None).await.unwrap_err().to_string(),
            format!("bundle_member_kind_refused: {found} is pinned where a program must be (requirement {name})")
        );
    }
}

/// L-held. While the program of a content launch runs, the Runtime holds
/// that launch's content for the program's own capsule id: every file the
/// walk read from the content bundle, by its path, and nothing of the page
/// or of the program. It is held for no one else and not kept afterwards. A
/// program started by its own CID has none.
#[tokio::test]
async fn the_content_of_a_launch_is_held_for_its_program_while_it_runs() {
    let publisher = key(84);
    let home = Home::trusting(&[&publisher]).await;
    let asks = serde_json::json!([{"resource": "elastos://test/bus/probe", "actions": ["read"]}]);
    let core = manifest_with("core", "asks", asks);
    let core = home
        .staged("core", &core, &calling_component(), &publisher)
        .await;
    let page = page_manifest("page", &[("core", &core)]).to_string();
    let page = home.staged("page", &page, b"a page", &publisher).await;
    let content = content_manifest("pictures", &[("page", &page)]).to_string();
    let content = home
        .staged("pictures", &content, b"a picture", &publisher)
        .await;

    // Asked from inside the bridge handler, which the core reaches because
    // it has asks: what is held for the caller, and for another id.
    type Seen = (String, Option<Vec<String>>, Option<Vec<String>>);
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let (record, runtime) = (seen.clone(), Arc::downgrade(&home.runtime));
    home.runtime
        .set_bridge_hostcall(Arc::new(move |_line, capsule, _principal| {
            let runtime = runtime.upgrade().expect("the Home");
            let (own, other) = (
                runtime.launch_paths_of(capsule),
                runtime.launch_paths_of("another"),
            );
            record
                .lock()
                .unwrap()
                .push((capsule.to_string(), own, other));
            Err("the test's bridge handler was reached".to_string())
        }));

    let refusal = home.run(&content, Some(PERSON)).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_start_failed", "{refusal}");
    let held = seen.lock().unwrap().clone();
    assert_eq!(held.len(), 1);
    let (capsule, own, other) = &held[0];
    let files = vec![ENTRYPOINT.to_string(), "capsule.json".to_string()];
    assert_eq!(own.as_ref(), Some(&files));
    assert_eq!(other, &None);
    assert_eq!(home.runtime.launch_paths_of(capsule), None, "not kept");

    // The same program started by its own CID: no content is held for it.
    let refusal = home.run(&core, Some(PERSON)).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_start_failed", "{refusal}");
    let held = seen.lock().unwrap().clone();
    assert_eq!(held.len(), 2);
    assert_eq!(held[1].1, None);
}

/// L-long. A content whose listing would be longer than a launch serves is
/// refused at the start, by name, before anything it pins is read. Here: 700
/// empty files, each under a path about four hundred bytes long (a whole
/// path must stay under what the file system allows).
#[tokio::test]
async fn content_whose_listing_is_too_long_is_refused_at_the_start() {
    let publisher = key(85);
    let home = Home::trusting(&[&publisher]).await;
    let core = home
        .staged("core", &manifest("core"), &quiet_component(), &publisher)
        .await;
    let page = page_manifest("page", &[("core", &core)]).to_string();
    let page = home.staged("page", &page, b"a page", &publisher).await;
    let manifest = content_manifest("long", &[("page", &page)]).to_string();
    let folder = home.bundle("long", &manifest, b"a picture");
    let deep = (0..2).fold(folder.clone(), |at, _| at.join("d".repeat(200)));
    fs::create_dir_all(&deep).unwrap();
    for file in 0..700 {
        fs::write(deep.join(format!("{file:03}")), b"").unwrap();
    }
    let content = home.stage(&folder, &publisher).await;
    let (result, walked) = home.run_watched(&content, None, BUNDLE_WALK_BUDGET).await;
    let refusal = result.unwrap_err();
    assert_eq!(
        refusal.code(),
        "bundle_content_listing_too_long",
        "{refusal}"
    );
    assert!(
        matches!(refusal, BundleRefusal::ContentListingTooLong(bytes) if bytes > 256 * 1024),
        "{refusal}"
    );
    assert_eq!(walked, [content.as_str()]);
}

/// L-cancel. A start that is cancelled while its program runs takes the
/// launch's content away at once. The program here is held inside its one
/// call to the bridge; the start is cancelled there; the content is gone
/// before the call returns, so the program, still running, finds none when
/// it looks again, and none is kept.
#[tokio::test]
async fn a_cancelled_start_takes_the_launchs_content_away() {
    let publisher = key(86);
    let home = Home::trusting(&[&publisher]).await;
    let asks = serde_json::json!([{"resource": "elastos://test/bus/probe", "actions": ["read"]}]);
    let core = manifest_with("core", "asks", asks);
    let core = home
        .staged("core", &core, &calling_component(), &publisher)
        .await;
    let page = page_manifest("page", &[("core", &core)]).to_string();
    let page = home.staged("page", &page, b"a page", &publisher).await;
    let content = content_manifest("pictures", &[("page", &page)]).to_string();
    let content = home
        .staged("pictures", &content, b"a picture", &publisher)
        .await;

    let (called, on_call) = std::sync::mpsc::channel::<String>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = Mutex::new(released);
    let looked: Arc<Mutex<Vec<Option<Vec<String>>>>> = Arc::default();
    let (record, runtime) = (looked.clone(), Arc::downgrade(&home.runtime));
    home.runtime
        .set_bridge_hostcall(Arc::new(move |_line, capsule, _principal| {
            let runtime = runtime.upgrade().expect("the Home");
            record
                .lock()
                .unwrap()
                .push(runtime.launch_paths_of(capsule));
            called.send(capsule.to_string()).unwrap();
            // Held here, inside the program's call, until the test says.
            released.lock().unwrap().recv().unwrap();
            record
                .lock()
                .unwrap()
                .push(runtime.launch_paths_of(capsule));
            Err("the test's bridge handler was reached".to_string())
        }));

    let (runtime, data) = (home.runtime.clone(), home.data());
    let start = tokio::spawn(async move {
        let person = Some(PERSON.to_string());
        let started = runtime.run_by_bundle(&data, &content, Vec::new(), person);
        started.await.map(|_| ())
    });
    let capsule = tokio::task::spawn_blocking(move || on_call.recv().unwrap())
        .await
        .unwrap();
    let files = vec![ENTRYPOINT.to_string(), "capsule.json".to_string()];
    assert_eq!(home.runtime.launch_paths_of(&capsule), Some(files.clone()));

    start.abort();
    assert!(start.await.unwrap_err().is_cancelled());
    assert_eq!(
        home.runtime.launch_paths_of(&capsule),
        None,
        "taken away at the cancel"
    );

    release.send(()).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while looked.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*looked.lock().unwrap(), [Some(files), None]);
}

/// A photo set as the start tests stage one: content pinning a page pinning a
/// quiet core that asks for nothing, so the start ends well. Returns the
/// content's CID and its manifest's text.
async fn staged_quiet_set(home: &Home, publisher: &SigningKey, picture: &[u8]) -> (String, String) {
    let core = home
        .staged("core", &manifest("core"), &quiet_component(), publisher)
        .await;
    let page = page_manifest("page", &[("core", &core)]).to_string();
    let page = home.staged("page", &page, b"a page", publisher).await;
    let content = content_manifest("pictures", &[("page", &page)]).to_string();
    let cid = home.staged("pictures", &content, picture, publisher).await;
    (cid, content)
}

/// D1a-keep. A launch opened for its page is kept after its start is over,
/// under an id of its own, for the person who opened it and the page the
/// content pins; it is read for them only, one output name or one content
/// file at a time, and for nobody else: another person, another page, an id
/// that is not kept. The program's own hold ended with its start.
#[tokio::test]
async fn a_launch_opened_for_its_page_is_kept_and_read_for_that_person_and_page() {
    let publisher = key(90);
    let home = Home::trusting(&[&publisher]).await;
    let picture = b"the bytes of a picture".to_vec();
    let (cid, content) = staged_quiet_set(&home, &publisher, &picture).await;

    let opened = home
        .runtime
        .open_for_page(&home.data(), &cid, PERSON)
        .await
        .unwrap();
    assert_eq!(opened.page, "page");
    assert_eq!(opened.id.len(), 32);
    assert_eq!(home.runtime.kept_launch_count(), 1);
    home.runtime
        .write_kept_output(&opened.id, "playlist.json", b"{\"items\":[]}");

    let read = |id: &str, person: &str, page: &str, what| {
        home.runtime.read_kept_launch(id, person, page, what)
    };
    use crate::page_launch::KeptRead::{Content, Output};
    assert_eq!(
        read(&opened.id, PERSON, "page", Content(ENTRYPOINT)),
        Some(picture.clone())
    );
    assert_eq!(
        read(&opened.id, PERSON, "page", Content("capsule.json")),
        Some(content.into_bytes())
    );
    assert_eq!(
        read(&opened.id, PERSON, "page", Output("playlist.json")),
        Some(b"{\"items\":[]}".to_vec())
    );
    assert_eq!(read(&opened.id, PERSON, "page", Output("other.json")), None);
    assert_eq!(
        read(&opened.id, PERSON, "page", Content("images/none.png")),
        None
    );
    assert_eq!(
        read(
            &opened.id,
            "person:local:another",
            "page",
            Content(ENTRYPOINT)
        ),
        None
    );
    assert_eq!(
        read(&opened.id, PERSON, "another-page", Content(ENTRYPOINT)),
        None
    );
    assert_eq!(
        read(&"0".repeat(32), PERSON, "page", Content(ENTRYPOINT)),
        None
    );
    assert!(home.runtime.list_capsules().await.is_empty());
}

/// D1a-paths. A content file is read at a plain path only, looked up as text:
/// the bare name (the listing), a leading `/`, an empty, `.` or `..` part and a
/// backslash are refused; an output name with a `/` is refused.
#[tokio::test]
async fn a_kept_launch_is_read_at_plain_paths_only() {
    let publisher = key(91);
    let home = Home::trusting(&[&publisher]).await;
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let opened = home
        .runtime
        .open_for_page(&home.data(), &cid, PERSON)
        .await
        .unwrap();
    use crate::page_launch::KeptRead::{Content, Output};
    let read = |what| {
        home.runtime
            .read_kept_launch(&opened.id, PERSON, "page", what)
    };
    assert!(read(Content(ENTRYPOINT)).is_some(), "the control");
    for path in [
        "",
        "/capsule.json",
        "./capsule.json",
        "x/../capsule.json",
        "..",
        "a//capsule.json",
        "capsule.json/",
        "a\\capsule.json",
    ] {
        assert_eq!(read(Content(path)), None, "{path:?}");
    }
    home.runtime
        .write_kept_output(&opened.id, "playlist.json", b"[]");
    assert!(read(Output("playlist.json")).is_some(), "the control");
    for name in ["../playlist.json", "x/playlist.json", "/playlist.json"] {
        assert_eq!(read(Output(name)), None, "{name:?}");
    }
    for (path, plain) in [
        ("a", true),
        ("images/01.png", true),
        ("", false),
        ("/a", false),
        ("a/./b", false),
        ("a/../b", false),
        ("..", false),
        ("a//b", false),
        ("a/", false),
        ("a\\b", false),
    ] {
        assert_eq!(
            crate::page_launch::plain_content_path(path),
            plain,
            "{path:?}"
        );
    }
}

/// D1a-bounds. One person keeps at most eight launches: the ninth open is
/// refused before anything runs, and nothing kept is dropped for it; another
/// person still opens. A kept launch goes when its time is up, and then reads
/// as nothing and frees its place.
#[tokio::test]
async fn a_person_keeps_eight_launches_and_each_goes_when_its_time_is_up() {
    let publisher = key(92);
    let home = Home::trusting(&[&publisher]).await;
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let data = home.data();
    let open = |person: &'static str| home.runtime.open_for_page(&data, &cid, person);
    let mut ids = Vec::new();
    for _ in 0..crate::page_launch::KEPT_PER_PRINCIPAL {
        ids.push(open(PERSON).await.unwrap().id);
    }
    let ninth = open(PERSON).await.unwrap_err();
    assert!(
        matches!(ninth, crate::page_launch::OpenRefusal::TooManyOpen),
        "{ninth:?}"
    );
    // Refused before the start: even a CID that would be refused by the
    // start is answered as the ninth.
    let ninth = home
        .runtime
        .open_for_page(&data, "not-a-cid", PERSON)
        .await
        .unwrap_err();
    assert!(
        matches!(ninth, crate::page_launch::OpenRefusal::TooManyOpen),
        "{ninth:?}"
    );
    assert_eq!(home.runtime.kept_launch_count(), 8);
    open("person:local:another").await.unwrap();
    assert_eq!(home.runtime.kept_launch_count(), 9);

    home.runtime.expire_kept_launches();
    use crate::page_launch::KeptRead::Content;
    assert_eq!(
        home.runtime
            .read_kept_launch(&ids[0], PERSON, "page", Content(ENTRYPOINT)),
        None
    );
    assert_eq!(home.runtime.kept_launch_count(), 0);
    open(PERSON).await.unwrap();
}

/// D1a-what. Only content is kept for a page: a program started by its own
/// CID is refused as not content, and a start that is refused keeps nothing
/// and says why. No person: refused before anything runs.
#[tokio::test]
async fn only_a_started_content_is_kept_for_its_page() {
    let publisher = key(93);
    let home = Home::trusting(&[&publisher]).await;
    let program = home
        .staged("core", &manifest("core"), &quiet_component(), &publisher)
        .await;
    let open = |cid: String, person: &'static str| {
        let data = home.data();
        let runtime = home.runtime.clone();
        async move { runtime.open_for_page(&data, &cid, person).await }
    };
    let refusal = open(program, PERSON).await.unwrap_err();
    assert!(
        matches!(refusal, crate::page_launch::OpenRefusal::NotContent),
        "{refusal:?}"
    );
    let refusal = open("not-a-cid".to_string(), PERSON).await.unwrap_err();
    assert!(
        matches!(&refusal, crate::page_launch::OpenRefusal::Start(start) if start.code() == "bundle_cid_form_invalid"),
        "{refusal:?}"
    );
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let refusal = open(cid, " ").await.unwrap_err();
    assert!(
        matches!(refusal, crate::page_launch::OpenRefusal::NoPrincipal),
        "{refusal:?}"
    );
    assert_eq!(home.runtime.kept_launch_count(), 0);
}

/// D1a-api. Through the Runtime API: the person's Home token opens the
/// content by its CID; the page's own token, bound to that launch with that
/// page as its executable, reads the output and a file, never to be stored.
/// Anything else alike is `not_found`: no token, the person's Home token, a
/// page token bound to another launch or naming another page, a path that is
/// not plain, an id that is not kept. A program, not content, is not opened.
/// (The routes sit behind the shell-only layers in `api/server.rs`.)
#[tokio::test]
async fn the_runtime_api_opens_and_reads_a_kept_launch_by_the_pages_token() {
    use crate::api::routes::kept_launch_test_tokens as tokens;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::{get, post};
    use tower::ServiceExt;
    let publisher = key(94);
    let home = Home::trusting(&[&publisher]).await;
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let data = home.data();
    let app = axum::Router::new()
        .route("/api/launch/open", post(crate::api::routes::open_launch))
        .route(
            "/api/launch/:id/output/:name",
            get(crate::api::routes::kept_launch_output),
        )
        .route(
            "/api/launch/:id/content/*path",
            get(crate::api::routes::kept_launch_content),
        )
        .layer(axum::Extension(Some(data.clone())))
        .layer(axum::Extension(home.runtime.clone()));
    let send = |request: Request<Body>| {
        let app = app.clone();
        async move {
            let answer = app.oneshot(request).await.unwrap();
            let status = answer.status();
            let store = answer.headers().get("cache-control").cloned();
            let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, store, body.to_vec())
        }
    };
    let open = |cid: &str, token: Option<String>| {
        let mut request = Request::builder()
            .method("POST")
            .uri("/api/launch/open")
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("x-elastos-home-token", token);
        }
        request
            .body(Body::from(serde_json::json!({"cid": cid}).to_string()))
            .unwrap()
    };
    let (status, _, _) = send(open(&cid, None)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no Home token, nothing opened"
    );
    assert_eq!(home.runtime.kept_launch_count(), 0);
    let (status, _, body) = send(open(&cid, Some(tokens::home(&data)))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let opened: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let (id, page) = (
        opened["id"].as_str().unwrap(),
        opened["page"].as_str().unwrap(),
    );
    assert_eq!(page, "page");
    home.runtime.write_kept_output(id, "playlist.json", b"[1]");

    let read = |uri: String, token: Option<String>| {
        let mut request = Request::builder().uri(uri);
        if let Some(token) = token {
            request = request.header("x-elastos-home-token", token);
        }
        request.body(Body::empty()).unwrap()
    };
    let own = || {
        Some(tokens::page(
            &data,
            &format!("elastos://launch/{id}"),
            "page",
        ))
    };
    let (status, store, body) = send(read(
        format!("/api/launch/{id}/output/playlist.json"),
        own(),
    ))
    .await;
    assert_eq!((status, body), (StatusCode::OK, b"[1]".to_vec()));
    assert_eq!(store.unwrap(), "no-store");
    let (status, _, body) = send(read(
        format!("/api/launch/{id}/content/{ENTRYPOINT}"),
        own(),
    ))
    .await;
    assert_eq!((status, body), (StatusCode::OK, b"a picture".to_vec()));

    let other = "0".repeat(32);
    for (uri, token) in [
        (format!("/api/launch/{id}/content/{ENTRYPOINT}"), None),
        (
            format!("/api/launch/{id}/content/{ENTRYPOINT}"),
            Some(tokens::home(&data)),
        ),
        (
            format!("/api/launch/{id}/content/{ENTRYPOINT}"),
            Some(tokens::page(
                &data,
                &format!("elastos://launch/{other}"),
                "page",
            )),
        ),
        (
            format!("/api/launch/{id}/content/{ENTRYPOINT}"),
            Some(tokens::page(
                &data,
                &format!("elastos://launch/{id}"),
                "another-page",
            )),
        ),
        (
            format!("/api/launch/{id}/content/x%2F..%2Fcapsule.json"),
            own(),
        ),
        (format!("/api/launch/{id}/output/other.json"), own()),
        (format!("/api/launch/{other}/content/{ENTRYPOINT}"), own()),
    ] {
        let (status, _, body) = send(read(uri.clone(), token)).await;
        assert_eq!(
            (status, body),
            (StatusCode::NOT_FOUND, b"not_found".to_vec()),
            "{uri}"
        );
    }

    let program = home
        .staged("core", &manifest("core"), &quiet_component(), &publisher)
        .await;
    let (status, _, body) = send(open(&program, Some(tokens::home(&data)))).await;
    assert_eq!(
        (status, body),
        (StatusCode::BAD_REQUEST, b"not_content".to_vec())
    );
    assert!(!tokens::person(&data).is_empty());
}

/// D1a-all. The Runtime keeps at most sixteen launches for everyone together:
/// two people fill it, a third person's open is refused as the Runtime's,
/// nothing kept is dropped for it, and when the time is up it opens.
#[tokio::test]
async fn the_runtime_keeps_sixteen_launches_for_everyone_together() {
    use crate::page_launch::{OpenRefusal, KEPT_IN_ALL, KEPT_PER_PRINCIPAL};
    let publisher = key(95);
    let home = Home::trusting(&[&publisher]).await;
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let data = home.data();
    let open = |person: &'static str| home.runtime.open_for_page(&data, &cid, person);
    assert_eq!(KEPT_IN_ALL, 2 * KEPT_PER_PRINCIPAL);
    for person in [PERSON, "person:local:second"] {
        for _ in 0..KEPT_PER_PRINCIPAL {
            open(person).await.unwrap();
        }
    }
    let third = open("person:local:third").await.unwrap_err();
    assert!(matches!(third, OpenRefusal::TooManyInAll), "{third:?}");
    assert_eq!(home.runtime.kept_launch_count(), KEPT_IN_ALL);
    home.runtime.expire_kept_launches();
    open("person:local:third").await.unwrap();
}

/// D1a-place. An open takes its place before its start runs, and the place
/// counts at once: with eight places taken and no start run, the next open is
/// refused before its start (a CID the start would refuse is answered as the
/// ninth). A place no launch fills reads as nothing. A place is given back
/// when its start is refused or what started is not content, so failed opens
/// leave nothing behind. Nine opens at once keep exactly eight.
#[tokio::test]
async fn a_place_is_taken_before_the_start_and_given_back_when_no_launch_fills_it() {
    use crate::page_launch::{take_place, KeptRead, OpenRefusal, KEPT_PER_PRINCIPAL};
    let publisher = key(96);
    let home = Home::trusting(&[&publisher]).await;
    let (cid, _) = staged_quiet_set(&home, &publisher, b"a picture").await;
    let program = home
        .staged("core", &manifest("core"), &quiet_component(), &publisher)
        .await;
    let data = home.data();
    let runtime = &home.runtime;

    let places: Vec<_> = (0..KEPT_PER_PRINCIPAL)
        .map(|_| take_place(&runtime.page_launches, PERSON).unwrap())
        .collect();
    let refused = runtime
        .open_for_page(&data, "not-a-cid", PERSON)
        .await
        .unwrap_err();
    assert!(matches!(refused, OpenRefusal::TooManyOpen), "{refused:?}");
    let (id, page) = (places[0].id().to_string(), "");
    assert_eq!(
        runtime.kept_launch_page(&id),
        None,
        "a place no launch fills"
    );
    assert_eq!(
        runtime.read_kept_launch(&id, PERSON, page, KeptRead::Content(ENTRYPOINT)),
        None
    );
    drop(places);
    assert_eq!(runtime.kept_launch_count(), 0, "the places went back");

    for _ in 0..3 * KEPT_PER_PRINCIPAL {
        let refused = runtime
            .open_for_page(&data, "not-a-cid", PERSON)
            .await
            .unwrap_err();
        assert!(matches!(refused, OpenRefusal::Start(_)), "{refused:?}");
        let refused = runtime
            .open_for_page(&data, &program, PERSON)
            .await
            .unwrap_err();
        assert!(matches!(refused, OpenRefusal::NotContent), "{refused:?}");
    }
    assert_eq!(runtime.kept_launch_count(), 0, "failed opens left nothing");

    let mut opens = tokio::task::JoinSet::new();
    for _ in 0..=KEPT_PER_PRINCIPAL {
        let (runtime, data, cid) = (runtime.clone(), data.clone(), cid.clone());
        opens.spawn(async move { runtime.open_for_page(&data, &cid, PERSON).await });
    }
    let opened: Vec<_> = opens.join_all().await;
    let kept = opened.iter().filter(|open| open.is_ok()).count();
    assert_eq!(kept, KEPT_PER_PRINCIPAL);
    assert!(opened
        .iter()
        .any(|open| matches!(open, Err(OpenRefusal::TooManyOpen))));
    assert_eq!(runtime.kept_launch_count(), KEPT_PER_PRINCIPAL);
}
