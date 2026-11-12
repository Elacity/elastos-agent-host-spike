//! Tests of the start by CID. Each row goes through `Runtime::run_by_bundle`
//! (or its observed form, which only adds the moment after the walk) on a
//! bundle put into the store by `stage_bundle`, and asserts the exact code of
//! a refusal. The bundles are built here; their CIDs come from the crate,
//! whose own vectors the lab's suite and the staging tests hold to recorded
//! values. Signatures are made by hand (`bundle_admission::tests::signed`).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use elastos_compute::providers::ComponentProvider;
use elastos_storage::providers::LocalFSProvider;

use crate::bundle_admission::tests::{did, key, signed};
use crate::bundle_admission::{
    bundle_signature_path, bundle_slot, BundleRefusal, BUNDLE_MANIFEST_KEYS,
};
use crate::runtime::tests::{
    component_manifest_json, component_with_extra_import, quiet_component,
};
use crate::runtime::Runtime;
use crate::stage_cmd::{bundle_cid, stage_bundle};

/// One call a component made to the bridge: the capsule's id, the principal
/// it ran for, and the ceiling recorded for it at that moment.
type Call = (String, Option<String>, Option<Vec<String>>);

/// The person the bus fixture component goes on for; for anyone else it ends
/// before it calls the bridge.
const PERSON: &str = "person:local:bus-conformance";

const ENTRYPOINT: &str = "app.component.wasm";

/// A Home with a real component provider, trusting `keys`, never in dev mode.
/// Its bridge records each call and refuses it, so nothing is ever granted.
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
                Err("refused by the test".to_string())
            }));
        home
    }

    /// Replace the keys this Home trusts.
    async fn trust(&self, keys: &[&SigningKey]) {
        let keys: Vec<String> = keys
            .iter()
            .map(|key| hex::encode(key.verifying_key().to_bytes()))
            .collect();
        self.runtime
            .configure_capsule_admission(self.dir.path(), &keys, false)
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
/// what runs is that component: the quiet one ends well and calls nothing;
/// the calling one makes its one call, for the person given, under an EMPTY
/// ceiling, and ends in its own error. No ceiling is left afterwards and
/// nothing was registered with the Runtime as a running capsule, though the
/// manifest sets projections.
#[tokio::test]
async fn a_staged_component_starts_by_its_cid_under_an_empty_ceiling() {
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
    assert_eq!(
        home.calls(),
        Vec::new(),
        "the quiet component calls nothing"
    );

    let refusal = home.run(&calling, Some(PERSON)).await.unwrap_err();
    assert_eq!(
        refusal.to_string(),
        "bundle_start_failed: Compute error: Component capsule denied: BusError::Internal(\"refused by the test\")"
    );
    let calls = home.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    let (capsule_id, principal_id, ceiling) = &calls[0];
    assert!(capsule_id.starts_with("component-"), "{capsule_id}");
    assert_eq!(principal_id.as_deref(), Some(PERSON));
    assert_eq!(
        ceiling.as_deref(),
        Some(&[][..]),
        "an empty ceiling, recorded"
    );
    assert_eq!(home.runtime.ceiling_of(capsule_id), None, "and taken away");
    assert!(home.runtime.list_capsules().await.is_empty());

    // Without the person the calling component ends before any call.
    let refusal = home.run(&calling, None).await.unwrap_err();
    assert_eq!(refusal.code(), "bundle_start_failed");
    assert_eq!(home.calls().len(), 1);
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
/// of it. What runs is the component that was walked (it calls the bridge
/// once); the replacement on disk (which calls nothing) is never read.
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
            || home.overwrite(&cid, ENTRYPOINT, &replacement),
        )
        .await;

    assert_eq!(
        fs::read(home.slot_file(&cid, ENTRYPOINT)).unwrap(),
        replacement
    );
    assert_eq!(
        home.calls().len(),
        1,
        "the walked component ran: {result:?}"
    );
    assert_eq!(result.unwrap_err().code(), "bundle_start_failed");
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

    fs::remove_file(bundle_signature_path(&home.data(), &cid.parse().unwrap())).unwrap();
    assert_eq!(code(home.run(&cid, None).await), "bundle_unsigned");
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
        ("asks", serde_json::json!([])),
        ("capabilities", serde_json::json!([])),
        ("permissions", serde_json::json!({})),
        ("requires", serde_json::json!([])),
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

/// The list holds every key the base manifest uses, and the two lists
/// together are every key of the Runtime's manifest type: a key added to
/// that type appears in neither and fails this test until it is placed.
#[test]
fn the_list_and_the_refused_keys_cover_the_manifest_type() {
    let refused = [
        "agent",
        "asks",
        "capabilities",
        "permissions",
        "requires",
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
}

/// The start by CID reads the slot through the one bounded walk and nothing
/// else: its body has one call of the bounded walk and none of the calls
/// that read a file again or fetch. A text pin of `run_by_bundle_observed`.
/// (The walk's name is split below so that the pin on the server's walks,
/// in `stage_cmd`, does not count this file.)
#[test]
fn the_start_by_cid_reads_the_slot_once_and_fetches_nothing() {
    let source = include_str!("runtime.rs");
    let start = source
        .find("pub(crate) async fn run_by_bundle_observed(")
        .unwrap();
    let body = &source[start..];
    let body = &body[..body.find("\n    }\n").unwrap()];
    let walk = ["checked_bundle", "_within("].concat();
    assert_eq!(body.matches(&walk).count(), 1);
    assert_eq!(body.matches("after_walk()").count(), 1);
    assert!(body.find(&walk).unwrap() < body.find("after_walk()").unwrap());
    for never in [
        "fs::read",
        "read_to_string",
        "read_admitted_entrypoint",
        "provider.load(",
        "fetch",
        "resolve_capsule_dir",
        "resource_authority_bounds",
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
    assert_eq!(body.matches("Vec::new(), args, principal_id").count(), 1);
}
