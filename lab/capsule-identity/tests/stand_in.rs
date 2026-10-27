//! M1 check B1 through the lab stand-in launcher, `StandInRuntime` in
//! `common`: a launch names the bundle by its lab CID only, and the stand-in
//! recomputes the CID from the stored bytes and checks the publisher's
//! signed package record before anything is launched. The stand-in is a lab
//! stand-in for the Runtime's launch route, not the Runtime: it runs nothing,
//! and these tests say nothing about what the Runtime does.
mod common;

use std::fs;
use std::path::{Path, PathBuf};

use capsule_identity::{
    checked_bundle, sign_package_record, verify_checked_package_record, LabCid, PackageRecord,
};
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use tempfile::TempDir;

/// The `agent-host` fixture published in a fresh temp parent: the parent,
/// the bundle folder inside it, and the folder's store entry.
struct Published {
    parent: TempDir,
    folder: PathBuf,
    entry: (String, PathBuf),
}

fn publish_agent_host() -> Published {
    let parent = temp_dir();
    let folder = parent.path().join("agent-host");
    assemble_at(&AGENT_HOST, &folder);
    let entry = published(&folder);
    assert_eq!(entry.0, AGENT_HOST_LAB_CID, "the fixture's pin");
    Published {
        parent,
        folder,
        entry,
    }
}

fn did_of(key: &SigningKey) -> String {
    elastos_identity::encode_signing_key_did(key)
}

fn sign(key: &SigningKey, bundle: &Path) -> PackageRecord {
    sign_package_record(key, bundle)
        .unwrap_or_else(|refusal| panic!("{}: {refusal}", bundle.display()))
}

/// A fresh stand-in for the published `agent-host`, its record signed by a
/// fresh test key whose DID is accepted, and that record.
fn signed_stand_in(published: &Published) -> (StandInRuntime, PackageRecord) {
    let key = fresh_signing_key();
    let record = sign(&key, &published.folder);
    let stand_in = StandInRuntime::new(
        [published.entry.clone()],
        vec![record.clone()],
        vec![did_of(&key)],
    );
    (stand_in, record)
}

fn launch_body() -> Value {
    json!({ "cid": AGENT_HOST_LAB_CID })
}

/// The stand-in lists no instance.
fn assert_none_listed(stand_in: &StandInRuntime, case: &str) {
    assert_eq!(
        stand_in.get_capsules(),
        json!({ "capsules": [] }),
        "{case}: a refused launch must leave no instance"
    );
}

/// The launch of `body` is refused with status 400 and exactly `reason`,
/// and no instance is listed after it.
fn assert_refused(stand_in: &mut StandInRuntime, body: &Value, reason: &str, case: &str) {
    assert_eq!(
        stand_in.post_capsules(body),
        Err((400, reason.to_owned())),
        "{case}"
    );
    assert_none_listed(stand_in, case);
}

/// The keys of a JSON object, sorted.
fn keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    keys
}

#[test]
fn standin_launches_a_signed_bundle_by_its_cid() {
    let published = publish_agent_host();
    let before = listing(published.parent.path());
    let (mut stand_in, _) = signed_stand_in(&published);

    let answer = stand_in
        .post_capsules(&launch_body())
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(keys(&answer), ["id", "name", "session_id", "status"]);
    assert_eq!(answer["status"], "launched");
    let manifest: Value =
        serde_json::from_slice(&read_fixture(&AGENT_HOST, "capsule.json")).expect("JSON");
    assert_eq!(answer["name"], manifest["name"]);
    assert!(answer["id"].as_str().is_some_and(|id| !id.is_empty()));
    assert!(answer["session_id"]
        .as_str()
        .is_some_and(|session| !session.is_empty()));

    let listed = stand_in.get_capsules();
    assert_eq!(keys(&listed), ["capsules"]);
    let capsules = listed["capsules"].as_array().expect("a list");
    assert_eq!(capsules.len(), 1, "exactly the one launched instance");
    let instance = &capsules[0];
    assert_eq!(
        keys(instance),
        ["cause", "id", "name", "session_id", "status"]
    );
    assert_eq!(instance["id"], answer["id"]);
    assert_eq!(instance["session_id"], answer["session_id"]);
    assert_eq!(instance["name"], answer["name"]);
    assert_eq!(instance["status"], "launched");
    assert_eq!(instance["cause"], Value::Null);

    // Launching wrote nothing: the bytes still give the pin, and nothing
    // was added next to the bundle.
    assert_eq!(named(&published.folder).to_string(), AGENT_HOST_LAB_CID);
    assert_eq!(listing(published.parent.path()), before);
}

#[test]
fn standin_launches_by_cid_only() {
    let published = publish_agent_host();
    let folder = published.folder.to_str().expect("a UTF-8 temp path");
    for (body, reason) in [
        (
            json!({ "path": folder }),
            "the launch body holds the field path: its only field is cid",
        ),
        (
            json!({ "cid": AGENT_HOST_LAB_CID, "path": folder }),
            "the launch body holds the field path: its only field is cid",
        ),
        (
            json!({}),
            "the launch body has no cid field: a launch names its bundle by lab CID",
        ),
        (
            json!({ "cid": 5 }),
            "the launch body's cid is 5, not a string",
        ),
        (
            json!([AGENT_HOST_LAB_CID]),
            "the launch body is not an object: it must be an object whose only field is cid",
        ),
    ] {
        // Each body goes to a stand-in that would launch `{"cid": ...}`.
        let (mut stand_in, _) = signed_stand_in(&published);
        assert_refused(&mut stand_in, &body, reason, &body.to_string());
    }
}

#[test]
fn standin_refuses_an_unsigned_or_mismatched_bundle_before_launch() {
    // (b) Text that is not a lab CID: the parse's own reason.
    let published = publish_agent_host();
    let (mut stand_in, _) = signed_stand_in(&published);
    let not_a_cid = "not-a-lab-cid";
    let parse = not_a_cid
        .parse::<LabCid>()
        .expect_err("not a lab CID")
        .to_string();
    assert_eq!(parse, not_a_lab_cid_text(not_a_cid));
    assert_refused(&mut stand_in, &json!({ "cid": not_a_cid }), &parse, "(b)");

    // (c) A lab CID with nothing stored under it.
    let (mut stand_in, _) = signed_stand_in(&published);
    assert_refused(
        &mut stand_in,
        &json!({ "cid": WEB_APP_LAB_CID }),
        &format!("no bundle is stored under {WEB_APP_LAB_CID}"),
        "(c)",
    );

    // (d) The manifest removed after publish: the walk's own refusal.
    let published = publish_agent_host();
    let (mut stand_in, _) = signed_stand_in(&published);
    fs::remove_file(published.folder.join("capsule.json")).expect("remove capsule.json");
    let walk = checked_bundle(&published.folder)
        .expect_err("no manifest")
        .to_string();
    assert_refused(&mut stand_in, &launch_body(), &walk, "(d)");

    // (e) One byte of asks.json changed after publish: the name compare's own
    // refusal, which names the published CID and the CID the bytes give now.
    let published = publish_agent_host();
    let (mut stand_in, _) = signed_stand_in(&published);
    let asks = published.folder.join("asks.json");
    let mut bytes = fs::read(&asks).expect("read asks.json");
    bytes[0] ^= 1;
    fs::write(&asks, &bytes).expect("write asks.json");
    let now = named(&published.folder).to_string();
    assert_ne!(now, AGENT_HOST_LAB_CID);
    let compare = checked(&published.folder)
        .check_name(AGENT_HOST_LAB_CID)
        .expect_err("the bytes changed")
        .to_string();
    assert!(compare.contains(AGENT_HOST_LAB_CID) && compare.contains(&now));
    assert_refused(&mut stand_in, &launch_body(), &compare, "(e)");

    // (f) No record binds the CID.
    let published = publish_agent_host();
    let key = fresh_signing_key();
    let mut stand_in = StandInRuntime::new([published.entry.clone()], vec![], vec![did_of(&key)]);
    assert_refused(
        &mut stand_in,
        &launch_body(),
        &format!("unsigned: no package record binds {AGENT_HOST_LAB_CID}"),
        "(f)",
    );

    // (g1) A record signed by a key whose DID is not accepted, and (g2) the
    // same with an empty accepted list: the record check's own refusal.
    let record = sign(&fresh_signing_key(), &published.folder);
    let checked_now = checked(&published.folder);
    for (accepted, case) in [
        (vec![did_of(&fresh_signing_key())], "(g1)"),
        (vec![], "(g2)"),
    ] {
        let own = verify_checked_package_record(&checked_now, &record, &accepted)
            .expect_err("not accepted")
            .to_string();
        assert_eq!(
            own,
            format!("signer {} is not in the accepted list", record.signer_did)
        );
        let mut stand_in =
            StandInRuntime::new([published.entry.clone()], vec![record.clone()], accepted);
        assert_refused(&mut stand_in, &launch_body(), &own, case);
    }

    // (g3) One signature byte flipped, by an accepted signer.
    let key = fresh_signing_key();
    let mut flipped = sign(&key, &published.folder);
    flipped.signature[0] ^= 1;
    let accepted = vec![did_of(&key)];
    let own = verify_checked_package_record(&checked_now, &flipped, &accepted)
        .expect_err("a flipped signature byte")
        .to_string();
    assert_eq!(
        own,
        format!(
            "signature by {} does not verify over {AGENT_HOST_LAB_CID}",
            flipped.signer_did
        )
    );
    let mut stand_in = StandInRuntime::new([published.entry.clone()], vec![flipped], accepted);
    assert_refused(&mut stand_in, &launch_body(), &own, "(g3)");
}
