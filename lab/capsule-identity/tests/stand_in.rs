//! M1 check B1 through the lane's CID fixture entry point over the shared
//! stand-in: a launch names the bundle by its lab CID only, the lane's one
//! identity check runs before anything is launched, and the shared `StandIn`
//! in `lab/agent-conformance/standin-runtime/mod.rs` owns the instance, its
//! session id, its lifecycle and its grants. A launched instance is handed
//! only the `asks.json` bytes of the checked, signed bundle (M1 check B2, the
//! part with no schema and no parse). This is lab test code: it runs nothing,
//! and these tests say nothing about what the Runtime does.
mod common;

#[path = "../../agent-conformance/standin-runtime/mod.rs"]
mod standin_runtime;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use capsule_identity::{
    checked_bundle, encode_chunked_files, encode_entries, encode_listed_files, sign_cid_record,
    sign_package_record, verify_checked_package_record, verify_cid_record, LabCid, PackageRecord,
    Refusal,
};
use common::*;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use standin_runtime::{Caller, Life, StandIn, Start};
use tempfile::TempDir;

/// The `agent-host` fixture published in a fresh temp parent: the parent,
/// the bundle folder inside it, and the folder's store entry.
struct Published {
    parent: TempDir,
    folder: PathBuf,
    entry: (String, Stored),
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

/// Admit the published fixture once at its stored path, with the checked
/// manifest's name and the test-supplied `Start::Ok`. Registration is a
/// fixture entry point: it neither verifies a publisher nor executes the
/// bundle.
fn register(shared: &mut StandIn, folder: &Path) {
    let name = checked(folder).manifest_name().to_owned();
    shared
        .admit_resident(
            folder.to_str().expect("a UTF-8 temp path"),
            &name,
            Start::Ok,
        )
        .expect("the stand-in admits the fixture path once");
}

/// A fresh lane store over the published `agent-host`, its record signed by a
/// fresh test key whose DID is accepted, and the one shared stand-in with that
/// fixture registered.
fn signed_stand_in(published: &Published) -> (StandInRuntime, StandIn) {
    let key = fresh_signing_key();
    let record = sign(&key, &published.folder);
    let lane = StandInRuntime::new([published.entry.clone()], vec![record], vec![did_of(&key)]);
    let mut shared = StandIn::new();
    register(&mut shared, &published.folder);
    (lane, shared)
}

fn launch_body() -> Value {
    json!({ "cid": AGENT_HOST_LAB_CID })
}

/// Launch the bundle the lab CID `cid` names through the adapted journey: the
/// lane's checks, then the one shared launch. The input is the lab CID only;
/// the shared `path` request is built after the checks.
fn launch_cid(
    lane: &mut StandInRuntime,
    shared: &mut StandIn,
    cid: &str,
) -> Result<Value, (u16, String)> {
    lane.commit_launch(&json!({ "cid": cid }), |body| {
        shared.post_capsules(Caller::Shell, body)
    })
}

/// The shared capsule list; each listed instance must hold exactly the shared
/// route's keys.
fn listed_instances(shared: &StandIn) -> Vec<Value> {
    let capsules = shared
        .get_capsules(Caller::Shell)
        .expect("the shell capsule list")["capsules"]
        .as_array()
        .expect("a list")
        .clone();
    for instance in &capsules {
        assert_eq!(
            keys(instance),
            ["cause", "id", "name", "session_id", "status"],
            "a listed instance holds no grant or token key"
        );
    }
    capsules
}

/// The shared list holds no instance.
fn assert_none_listed(shared: &StandIn, case: &str) {
    assert_eq!(
        listed_instances(shared),
        Vec::<Value>::new(),
        "{case}: a refused launch must leave no instance"
    );
}

/// Register the saved listing under its printed CID: the shared fixture's
/// path and display name are that CID, the one name a listing has.
fn register_listing(shared: &mut StandIn, cid: &str) {
    shared
        .admit_resident(&listing_path(cid), &listing_path(cid), Start::Ok)
        .expect("the stand-in admits the listing fixture once");
}

/// A fresh lane store over the saved listing `entry`, its record signed by a
/// fresh test key whose DID is accepted, and the one shared stand-in with the
/// listing registered under its printed CID.
fn signed_listing(entry: (String, Stored)) -> (StandInRuntime, StandIn) {
    let cid: LabCid = entry.0.parse().expect("the listing's printed lab CID");
    let key = fresh_signing_key();
    let record = sign_cid_record(&key, cid);
    let lane = StandInRuntime::new([entry], vec![record], vec![did_of(&key)]);
    let mut shared = StandIn::new();
    register_listing(&mut shared, &cid.to_string());
    (lane, shared)
}

/// Launch the listing the printed lab CID `cid` names, asserting that the
/// launch happened: a refusal fails the test as an assertion, with the status
/// and reason.
fn launched_listing(lane: &mut StandInRuntime, shared: &mut StandIn, cid: &str) -> Value {
    let answer = launch_cid(lane, shared, cid);
    assert!(answer.is_ok(), "the listing launch was refused: {answer:?}");
    let answer = answer.expect("the launch succeeded");
    assert_eq!(keys(&answer), ["id", "name", "session_id", "status"]);
    answer
}

/// The listing journey through the shared stand-in: `starting`, then the
/// simulated start completes to `running`; the display name is the printed
/// CID, the asks snapshot is absent and the grant view is empty.
fn assert_listing_journey(lane: &mut StandInRuntime, shared: &mut StandIn, cid: &str) {
    let answer = launched_listing(lane, shared, cid);
    assert_eq!(
        answer["status"], "starting",
        "the shared launch answers starting"
    );
    assert_eq!(
        answer["session_id"], answer["id"],
        "the shared instance uses its id as its Bus session"
    );
    assert_eq!(answer["name"], cid, "the display name is the printed CID");

    let listed = listed_instances(shared);
    assert_eq!(listed.len(), 1, "exactly the one launched instance");
    let instance = &listed[0];
    assert_eq!(instance["id"], answer["id"]);
    assert_eq!(instance["session_id"], answer["session_id"]);
    assert_eq!(instance["name"], cid);
    assert_eq!(instance["status"], "starting");
    assert_eq!(instance["cause"], "", "the shared list's empty cause");

    let id = answer["id"].as_str().expect("an id");
    shared
        .finish_start(id)
        .expect("the stand-in applies Start::Ok");
    let listed = listed_instances(shared);
    assert_eq!(
        listed[0]["status"], "running",
        "finish_start moves that instance to running"
    );
    assert_eq!(listed[0]["cause"], "");

    let session = answer["session_id"].as_str().expect("a session id");
    assert_eq!(
        lane.asks_of(session),
        None,
        "a digest listing holds no asks bytes"
    );
    assert_eq!(
        grant_view(lane, shared),
        Vec::<Value>::new(),
        "a listing launch adds no grant"
    );

    // The view reads the shared state: one grant seeded for another session
    // after the launch is listed, and the listing's own session holds none.
    seed_grant(
        shared,
        99,
        "another-session",
        "localhost://Users/self/Documents/notes.md",
        "write",
        "session",
    );
    let held = grant_view(lane, shared);
    assert_eq!(held.len(), 1, "the seeded grant only: {held:?}");
    assert_eq!(held[0]["session_id"], "another-session");
    assert!(
        held.iter().all(|grant| grant["session_id"] != session),
        "the listing launch adds no grant"
    );
}

/// The launch of `body` is refused with status 400 and exactly `reason`, and
/// the shared list holds no instance after it.
fn assert_refused(
    lane: &mut StandInRuntime,
    shared: &mut StandIn,
    body: &Value,
    reason: &str,
    case: &str,
) {
    assert_eq!(
        lane.commit_launch(body, |body| shared.post_capsules(Caller::Shell, body)),
        Err((400, reason.to_owned())),
        "{case}"
    );
    assert_none_listed(shared, case);
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
    let (mut lane, mut shared) = signed_stand_in(&published);

    let answer = launch_cid(&mut lane, &mut shared, AGENT_HOST_LAB_CID)
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(keys(&answer), ["id", "name", "session_id", "status"]);
    assert_eq!(answer["status"], "starting");
    assert_eq!(
        answer["session_id"], answer["id"],
        "the shared instance uses its id as its Bus session"
    );
    let manifest: Value =
        serde_json::from_slice(&read_fixture(&AGENT_HOST, "capsule.json")).expect("JSON");
    assert_eq!(answer["name"], manifest["name"]);

    let listed = listed_instances(&shared);
    assert_eq!(listed.len(), 1, "exactly the one launched instance");
    let instance = &listed[0];
    assert_eq!(instance["id"], answer["id"]);
    assert_eq!(instance["session_id"], answer["session_id"]);
    assert_eq!(instance["name"], answer["name"]);
    assert_eq!(instance["status"], "starting");
    assert_eq!(instance["cause"], "", "the shared list's empty cause");

    let id = answer["id"].as_str().expect("an id");
    shared
        .finish_start(id)
        .expect("the stand-in applies Start::Ok");
    let listed = listed_instances(&shared);
    assert_eq!(
        listed[0]["status"], "running",
        "finish_start moves that instance to running"
    );
    assert_eq!(listed[0]["cause"], "");

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
        // Each body goes to a store that would launch `{"cid": ...}`.
        let (mut lane, mut shared) = signed_stand_in(&published);
        assert_refused(&mut lane, &mut shared, &body, reason, &body.to_string());
    }
}

#[test]
fn standin_refuses_an_unsigned_or_mismatched_bundle_before_launch() {
    // (b) Text that is not a lab CID: the parse's own reason.
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let not_a_cid = "not-a-lab-cid";
    let parse = not_a_cid
        .parse::<LabCid>()
        .expect_err("not a lab CID")
        .to_string();
    assert_eq!(parse, not_a_lab_cid_text(not_a_cid));
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": not_a_cid }),
        &parse,
        "(b)",
    );

    // (c) A lab CID with nothing stored under it.
    let (mut lane, mut shared) = signed_stand_in(&published);
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": WEB_APP_LAB_CID }),
        &format!("no bundle is stored under {WEB_APP_LAB_CID}"),
        "(c)",
    );

    // (d) The manifest removed after publish: the walk's own refusal.
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    fs::remove_file(published.folder.join("capsule.json")).expect("remove capsule.json");
    let walk = checked_bundle(&published.folder)
        .expect_err("no manifest")
        .to_string();
    assert_refused(&mut lane, &mut shared, &launch_body(), &walk, "(d)");

    // (e) One byte of asks.json changed after publish: the name compare's own
    // refusal, which names the published CID and the CID the bytes give now.
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
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
    assert_refused(&mut lane, &mut shared, &launch_body(), &compare, "(e)");

    // (f) No record binds the CID.
    let published = publish_agent_host();
    let key = fresh_signing_key();
    let mut lane = StandInRuntime::new([published.entry.clone()], vec![], vec![did_of(&key)]);
    let mut shared = StandIn::new();
    register(&mut shared, &published.folder);
    assert_refused(
        &mut lane,
        &mut shared,
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
        let mut lane =
            StandInRuntime::new([published.entry.clone()], vec![record.clone()], accepted);
        let mut shared = StandIn::new();
        register(&mut shared, &published.folder);
        assert_refused(&mut lane, &mut shared, &launch_body(), &own, case);
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
    let mut lane = StandInRuntime::new([published.entry.clone()], vec![flipped], accepted);
    let mut shared = StandIn::new();
    register(&mut shared, &published.folder);
    assert_refused(&mut lane, &mut shared, &launch_body(), &own, "(g3)");
}

#[test]
fn standin_launch_does_not_depend_on_record_order() {
    // Several package records can bind one CID. The launch goes on when at
    // least one of them passes the record check, whatever their order.
    let published = publish_agent_host();
    let accepted_key = fresh_signing_key();
    let accepted_record = sign(&accepted_key, &published.folder);
    let unaccepted_record = sign(&fresh_signing_key(), &published.folder);
    for (records, case) in [
        (
            vec![unaccepted_record.clone(), accepted_record.clone()],
            "[unaccepted, accepted]",
        ),
        (
            vec![accepted_record.clone(), unaccepted_record.clone()],
            "[accepted, unaccepted]",
        ),
    ] {
        let mut lane = StandInRuntime::new(
            [published.entry.clone()],
            records,
            vec![did_of(&accepted_key)],
        );
        let mut shared = StandIn::new();
        register(&mut shared, &published.folder);
        let answer = launch_cid(&mut lane, &mut shared, AGENT_HOST_LAB_CID)
            .unwrap_or_else(|(status, reason)| panic!("{case}: refused with {status}: {reason}"));
        assert_eq!(answer["status"], "starting", "{case}");
        let listed = listed_instances(&shared);
        assert_eq!(listed.len(), 1, "{case}: exactly one instance");
        assert_eq!(listed[0]["id"], answer["id"], "{case}");
    }

    // When no record passes, the answer is the first one's own refusal, in
    // store order, and nothing is launched.
    let first = sign(&fresh_signing_key(), &published.folder);
    let second = sign(&fresh_signing_key(), &published.folder);
    assert_ne!(first.signer_did, second.signer_did);
    let accepted = vec![did_of(&accepted_key)];
    let own = verify_checked_package_record(&checked(&published.folder), &first, &accepted)
        .expect_err("not accepted")
        .to_string();
    assert_eq!(
        own,
        format!("signer {} is not in the accepted list", first.signer_did)
    );
    let mut lane = StandInRuntime::new([published.entry.clone()], vec![first, second], accepted);
    let mut shared = StandIn::new();
    register(&mut shared, &published.folder);
    assert_refused(
        &mut lane,
        &mut shared,
        &launch_body(),
        &own,
        "two unaccepted signers",
    );
}

/// Launch the published `agent-host` by its CID; the answer must hold exactly
/// the shared launch keys.
fn launched(lane: &mut StandInRuntime, shared: &mut StandIn) -> Value {
    let answer = launch_cid(lane, shared, AGENT_HOST_LAB_CID)
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(
        keys(&answer),
        ["id", "name", "session_id", "status"],
        "the launch answer holds no grant or token key"
    );
    answer
}

/// The entries of the shared grant view, which must answer under the
/// `all_sessions_live` marker through the lane's one seam.
fn grant_view(lane: &StandInRuntime, shared: &StandIn) -> Vec<Value> {
    let view = lane.live_grants(|| {
        shared
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .unwrap_or_else(|(status, reason)| {
                panic!("the shared grant view refused with {status}: {reason}")
            })
    });
    assert_eq!(keys(&view), ["capabilities", "scope"]);
    assert_eq!(view["scope"], "all_sessions_live");
    view["capabilities"].as_array().expect("a list").clone()
}

/// Seed the `number`th live grant of `session_id` through the shared seam.
fn seed_grant(
    shared: &mut StandIn,
    number: usize,
    session_id: &str,
    resource: &str,
    action: &str,
    duration: &str,
) {
    shared.seed_grant(
        &grant_request_id(number),
        session_id,
        resource,
        action,
        duration,
        number as u64,
        Life::Live,
        false,
    );
}

#[test]
fn standin_valid_signature_alone_yields_no_grant() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    // The manifest asks for a grant, so a launch that turned asks into grants
    // would show here.
    let manifest: Value =
        serde_json::from_slice(&read_fixture(&AGENT_HOST, "capsule.json")).expect("JSON");
    assert!(manifest["capabilities"]
        .as_array()
        .is_some_and(|asked| !asked.is_empty()));

    // The launch passes the record check, so the publisher's signature is
    // valid, and still no grant is held.
    let first = launched(&mut lane, &mut shared);
    assert_eq!(listed_instances(&shared).len(), 1);
    let held = grant_view(&lane, &shared);
    assert!(
        !held
            .iter()
            .any(|entry| entry["session_id"] == first["session_id"]),
        "a valid signature alone must yield no grant for the launched session: {held:?}"
    );
    assert_eq!(held, Vec::<Value>::new(), "no grant is held at all");

    // A second launch gives a second session, and still no grant.
    let second = launched(&mut lane, &mut shared);
    assert_ne!(second["session_id"], first["session_id"]);
    assert_eq!(listed_instances(&shared).len(), 2);
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "no grant is held after a second launch"
    );
}

#[test]
fn standin_grant_view_lists_a_seeded_grant() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let answer = launched(&mut lane, &mut shared);
    let session = answer["session_id"].as_str().expect("a session id");
    let resource = "localhost://Users/self/.AppData/Agents/agent-host/journal";
    seed_grant(&mut shared, 1, session, resource, "write", "session");

    let held = grant_view(&lane, &shared);
    assert_eq!(held.len(), 1, "exactly the one seeded grant: {held:?}");
    let entry = &held[0];
    assert_eq!(
        keys(entry),
        [
            "action",
            "duration",
            "granted_at",
            "request_id",
            "resource",
            "session_id"
        ]
    );
    assert_eq!(entry["session_id"], session);
    assert_eq!(entry["resource"], resource);
    assert_eq!(entry["action"], "write");
    assert_eq!(entry["duration"], "session");
    assert_eq!(entry["request_id"], grant_request_id(1));
    assert!(entry["granted_at"].is_u64());

    // The seed is not a launch: the instance list is unchanged.
    assert_eq!(listed_instances(&shared).len(), 1);
}

#[test]
fn standin_grant_view_lists_every_held_grant_of_every_session() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let first = launched(&mut lane, &mut shared);
    let second = launched(&mut lane, &mut shared);
    let a = first["session_id"].as_str().expect("a session id");
    let b = second["session_id"].as_str().expect("a session id");
    assert_ne!(a, b, "two launches give two sessions");

    // One grant for A, then two for B, each a different (resource, action).
    let seeded = [
        (
            a,
            "localhost://Users/self/.AppData/Agents/agent-host/journal",
            "write",
            "session",
        ),
        (
            b,
            "localhost://Users/self/Documents/notes.md",
            "read",
            "once",
        ),
        (
            b,
            "localhost://Users/self/.AppData/Agents/agent-host/cache",
            "delete",
            "session",
        ),
    ];
    for (number, (session, resource, action, duration)) in seeded.iter().enumerate() {
        seed_grant(&mut shared, number + 1, session, resource, action, duration);
    }

    let held = grant_view(&lane, &shared);
    assert_eq!(held.len(), 3, "every held grant is listed: {held:?}");
    let mut listed: Vec<(&str, &str, &str, &str)> = held
        .iter()
        .map(|entry| {
            let text = |key: &str| entry[key].as_str().expect("a string");
            (
                text("session_id"),
                text("resource"),
                text("action"),
                text("duration"),
            )
        })
        .collect();
    listed.sort();
    let mut expected = seeded.to_vec();
    expected.sort();
    assert_eq!(listed, expected, "each entry is a seeded grant, as seeded");

    for session in [a, b] {
        assert!(
            held.iter().any(|entry| entry["session_id"] == session),
            "the grants of session {session} are listed: {held:?}"
        );
    }
    let request_ids: BTreeSet<&str> = held
        .iter()
        .map(|entry| entry["request_id"].as_str().expect("a request id"))
        .collect();
    assert_eq!(
        request_ids.len(),
        3,
        "three different request ids: {held:?}"
    );

    // Seeding is not a launch: the instance list is unchanged.
    assert_eq!(listed_instances(&shared).len(), 2);
}

/// Change one byte of the stored `asks.json` in `folder`; the changed bytes.
fn change_stored_asks(folder: &Path) -> Vec<u8> {
    let asks = folder.join("asks.json");
    let mut bytes = fs::read(&asks).expect("read asks.json");
    bytes[0] ^= 1;
    fs::write(&asks, &bytes).expect("write asks.json");
    bytes
}

#[test]
fn standin_hands_an_instance_only_its_signed_asks_bytes() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let signed = read_fixture(&AGENT_HOST, "asks.json");

    let answer = launched(&mut lane, &mut shared);
    let session = answer["session_id"].as_str().expect("a session id");
    assert_eq!(
        lane.asks_of(session),
        Some(signed.clone()),
        "the instance is handed the committed asks.json bytes"
    );

    // One byte of the stored asks.json changes after the launch.
    let changed = change_stored_asks(&published.folder);
    assert_ne!(changed, signed);
    assert_eq!(
        lane.asks_of(session),
        Some(signed),
        "a change on disk after launch must not reach the instance"
    );

    // A second launch of the same CID is refused by case (e), the name
    // compare's own refusal, and leaves no new instance and no grant.
    let now = named(&published.folder).to_string();
    assert_ne!(now, AGENT_HOST_LAB_CID);
    let compare = checked(&published.folder)
        .check_name(AGENT_HOST_LAB_CID)
        .expect_err("the bytes changed")
        .to_string();
    assert!(compare.contains(AGENT_HOST_LAB_CID) && compare.contains(&now));
    assert_eq!(
        launch_cid(&mut lane, &mut shared, AGENT_HOST_LAB_CID),
        Err((400, compare)),
        "(e) after the change"
    );
    assert_eq!(listed_instances(&shared).len(), 1, "no new instance");
    assert_eq!(grant_view(&lane, &shared), Vec::<Value>::new(), "no grant");
}

/// The lane's after-walk hook: change one byte of the stored `asks.json`.
fn change_stored_asks_after_the_walk(folder: &Path) {
    change_stored_asks(folder);
}

#[test]
fn standin_takes_the_asks_from_the_walk_not_the_folder() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let signed = read_fixture(&AGENT_HOST, "asks.json");
    lane.set_after_walk(change_stored_asks_after_the_walk);

    // The walk read the signed bytes, so the name compare and the record
    // check pass, and the shared launch goes on.
    let answer = launched(&mut lane, &mut shared);
    assert_eq!(answer["status"], "starting");
    let session = answer["session_id"].as_str().expect("a session id");

    // The hook ran: the stored asks.json changed between the walk and the
    // launch.
    let on_disk = fs::read(published.folder.join("asks.json")).expect("read asks.json");
    assert_ne!(
        on_disk, signed,
        "the hook must have changed the stored asks.json"
    );

    // The instance is handed the bytes the walk read, not the folder's.
    assert_eq!(
        lane.asks_of(session),
        Some(signed),
        "a change on disk between the walk and the launch must not reach the instance"
    );
    assert_eq!(listed_instances(&shared).len(), 1);
    assert_eq!(grant_view(&lane, &shared), Vec::<Value>::new(), "no grant");
}

#[test]
fn standin_gives_each_session_its_own_asks() {
    let agent_host = publish_agent_host();
    let parent = temp_dir();
    let web_app = parent.path().join("web-app");
    assemble_at(&WEB_APP, &web_app);
    let web_entry = published(&web_app);
    assert_eq!(web_entry.0, WEB_APP_LAB_CID, "the fixture's pin");
    assert!(
        checked(&web_app)
            .entries()
            .iter()
            .all(|entry| entry.path != "asks.json"),
        "web-app has no asks.json"
    );
    let signed = read_fixture(&AGENT_HOST, "asks.json");

    for order in [
        [AGENT_HOST_LAB_CID, WEB_APP_LAB_CID],
        [WEB_APP_LAB_CID, AGENT_HOST_LAB_CID],
    ] {
        let case = format!("launched in the order {order:?}");
        let key = fresh_signing_key();
        let records = vec![sign(&key, &agent_host.folder), sign(&key, &web_app)];
        let mut lane = StandInRuntime::new(
            [agent_host.entry.clone(), web_entry.clone()],
            records,
            vec![did_of(&key)],
        );
        let mut shared = StandIn::new();
        register(&mut shared, &agent_host.folder);
        register(&mut shared, &web_app);
        let mut sessions = Vec::new();
        for cid in order {
            let answer =
                launch_cid(&mut lane, &mut shared, cid).unwrap_or_else(|(status, reason)| {
                    panic!("{case}: refused with {status}: {reason}")
                });
            assert_eq!(keys(&answer), ["id", "name", "session_id", "status"]);
            let session = answer["session_id"].as_str().expect("a session id");
            sessions.push((cid, session.to_owned()));
        }
        let session_of = |wanted: &str| {
            sessions
                .iter()
                .find(|(cid, _)| *cid == wanted)
                .map(|(_, session)| session.clone())
                .expect("the CID was launched")
        };
        assert_eq!(
            lane.asks_of(&session_of(AGENT_HOST_LAB_CID)),
            Some(signed.clone()),
            "{case}: agent-host's session answers its own asks.json bytes"
        );
        assert_eq!(
            lane.asks_of(&session_of(WEB_APP_LAB_CID)),
            None,
            "{case}: web-app has no asks.json, so its session answers none"
        );
        assert_eq!(
            lane.asks_of("no-such-session"),
            None,
            "{case}: an unknown session answers none"
        );
        assert_eq!(listed_instances(&shared).len(), 2, "{case}");
        assert_eq!(grant_view(&lane, &shared), Vec::<Value>::new(), "{case}");
    }
}

#[test]
fn standin_shared_stop_updates_the_same_instances_and_grants() {
    let published = publish_agent_host();
    let (mut lane, mut shared) = signed_stand_in(&published);
    let first = launched(&mut lane, &mut shared);
    let second = launched(&mut lane, &mut shared);
    let a = first["id"].as_str().expect("an id").to_owned();
    let b = second["id"].as_str().expect("an id").to_owned();
    assert_ne!(a, b, "two launches give two instances");

    shared.finish_start(&a).expect("Start::Ok for the first");
    shared.finish_start(&b).expect("Start::Ok for the second");
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "a valid signature alone still yields no grant before the seeds"
    );

    seed_grant(
        &mut shared,
        1,
        &a,
        "localhost://Users/self/.AppData/Agents/agent-host/journal",
        "write",
        "session",
    );
    seed_grant(
        &mut shared,
        2,
        &b,
        "localhost://Users/self/Documents/notes.md",
        "read",
        "once",
    );
    let held = grant_view(&lane, &shared);
    assert_eq!(held.len(), 2, "one live grant for each instance");

    let stopped = lane
        .apply_stop(|| shared.delete_capsule(Caller::Shell, &a, &json!({ "reason": "test stop" })))
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(stopped, Value::Null, "the shared stop answers null");

    let listed = listed_instances(&shared);
    let stopped_entry = listed
        .iter()
        .find(|entry| entry["id"] == a.as_str())
        .expect("the stopped instance is listed");
    assert_eq!(stopped_entry["status"], "stopped");
    assert_eq!(stopped_entry["cause"], "stopped: test stop");
    let sibling = listed
        .iter()
        .find(|entry| entry["id"] == b.as_str())
        .expect("the sibling is listed");
    assert_eq!(sibling["status"], "running", "the sibling stays running");
    assert_eq!(sibling["cause"], "");

    let held = grant_view(&lane, &shared);
    assert_eq!(
        held.len(),
        1,
        "the stopped session's grant is gone: {held:?}"
    );
    assert_eq!(held[0]["session_id"], b.as_str());
    assert_eq!(held[0]["request_id"], grant_request_id(2));
    assert_eq!(
        held[0]["resource"],
        "localhost://Users/self/Documents/notes.md"
    );
}

#[test]
fn standin_launches_the_photo_listing_by_its_cid() {
    // The five files of the photo stand-in copy, listed as its walk lists
    // them: the pin is `encode_listed_files` of that listing. The exact
    // folder of those five files is not a store input here, because the
    // Runtime's manifest type refuses its `viewer` object.
    let entry = published_listing(photo_listing());
    assert_eq!(entry.0, PHOTO_STAND_IN_LAB_CID, "the listing's pin");
    let (mut lane, mut shared) = signed_listing(entry);

    assert_listing_journey(&mut lane, &mut shared, PHOTO_STAND_IN_LAB_CID);

    // The exact PH6 folder still gives ManifestUnparsed: this lane names
    // these five files only from a listing, never from that folder.
    let folder = temp_dir();
    for entry in photo_stand_in_entries() {
        write_file(folder.path(), &entry.path, &entry.content);
    }
    let refusal = checked_bundle(folder.path()).expect_err("the exact PH6 folder is refused");
    assert!(
        matches!(refusal, Refusal::ManifestUnparsed(_)),
        "another refusal: {refusal}"
    );
    let text = refusal.to_string();
    assert!(text.contains("refused to parse capsule.json"), "{text}");
}

#[test]
fn standin_launches_a_chunked_photo_listing_by_its_cid() {
    // The five files and the three-leaf `core/big.bin`, given as each raw
    // leaf's SHA-256: the chunked listing names the same closure as the
    // entries do.
    let files = photo_chunked_listing();
    let entries = photo_entries_with_big_bin();
    let cid = encode_chunked_files(&files)
        .unwrap_or_else(|refusal| panic!("the chunked listing: {refusal}"));
    assert_eq!(
        cid.to_string(),
        encode_entries(&entries)
            .unwrap_or_else(|refusal| panic!("the entries: {refusal}"))
            .to_string(),
        "the chunked listing and the entries name one closure"
    );

    let entry = published_chunked_listing(files);
    assert_eq!(entry.0, cid.to_string());
    let cid_text = entry.0.clone();
    let (mut lane, mut shared) = signed_listing(entry);
    assert_listing_journey(&mut lane, &mut shared, &cid_text);

    // The one-digest API still refuses the big file: its one SHA-256 names a
    // single raw leaf.
    let refusal = encode_listed_files(&listed_files(&entries))
        .expect_err("a listed file over one leaf is refused");
    assert_eq!(
        refusal,
        Refusal::FileOverChunkLimit {
            path: BIG_BIN.to_owned(),
            length: big_bin_bytes().len()
        }
    );
}

#[test]
fn standin_folder_and_listing_names_share_the_library_compare() {
    let code = library_code();
    let adapter = include_str!("common/mod.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let prepare = library_item(&adapter, "fn checked_launch(");
    let folder = prepare
        .split("Stored::Folder(folder) =>")
        .nth(1)
        .expect("the folder preparation")
        .split("Stored::Listing(listing) =>")
        .next()
        .expect("the end of folder preparation");
    assert_eq!(folder.matches("checked.check_name(&cid)").count(), 1);
    for arm in ["Stored::Listing(listing) =>", "Stored::Chunked(files) =>"] {
        let listing = prepare.split(arm).nth(1).expect("the listing arm");
        let listing = listing.split("\n            }").next().unwrap();
        assert_eq!(
            listing
                .matches("Self::require_listing_name(actual, &cid)?")
                .count(),
            1,
            "{arm} uses the shared listing name check"
        );
    }
    for (body, call) in [
        (
            library_item(&adapter, "fn require_listing_name("),
            "actual.check_name(claimed).map_err(said)?",
        ),
        (
            library_item(&code, "pub fn check_name(&self"),
            "compare_name(self.cid, claimed_digits, claimed)",
        ),
        (
            library_item(&code, "pub fn check_name(self,"),
            "compare_name(self, claimed_digits, claimed)",
        ),
    ] {
        assert_eq!(body.matches(call).count(), 1, "{body}");
        assert!(!body.contains("Refusal::"), "a second refusal path: {body}");
    }
    assert_eq!(
        library_item(&adapter, "impl StandInRuntime {")
            .matches("Refusal::NameMismatch")
            .count(),
        0
    );
    assert_eq!(
        code.matches("return Err(Refusal::NameMismatch {").count(),
        1
    );
}

#[test]
fn standin_refuses_a_changed_listing_before_shared_launch() {
    // The one-digest arm: a saved file digest changes after publish, and the
    // store keeps the old CID.
    let listing = photo_listing();
    let (claimed, mut stored) = published_listing(listing.clone());
    assert_eq!(claimed, PHOTO_STAND_IN_LAB_CID);
    match &mut stored {
        Stored::Listing(saved) => saved[2].sha256[0] ^= 1,
        _ => panic!("the store holds the listing"),
    }
    let mut changed = listing;
    changed[2].sha256[0] ^= 1;
    let actual = encode_listed_files(&changed)
        .unwrap_or_else(|refusal| panic!("the changed listing: {refusal}"));
    assert_ne!(actual.to_string(), claimed);
    let reason = Refusal::NameMismatch {
        actual,
        claimed: claimed.clone(),
    }
    .to_string();
    let key = fresh_signing_key();
    let requested: LabCid = claimed.parse().expect("the listing's printed lab CID");
    let record = sign_cid_record(&key, requested);
    let mut lane = StandInRuntime::new(
        [(claimed.clone(), stored)],
        vec![record],
        vec![did_of(&key)],
    );
    let mut shared = StandIn::new();
    register_listing(&mut shared, &claimed);
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": claimed }),
        &reason,
        "the changed one-digest listing",
    );
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "the changed one-digest listing adds no grant"
    );

    // The chunked arm: one leaf digest of the three-leaf big file changes
    // after publish.
    let files = photo_chunked_listing();
    let (claimed, mut stored) = published_chunked_listing(files.clone());
    match &mut stored {
        Stored::Chunked(saved) => {
            let at = saved
                .iter()
                .position(|file| file.path == BIG_BIN)
                .expect("the big file's listing");
            saved[at].chunk_sha256[0][0] ^= 1;
        }
        _ => panic!("the store holds the chunked listing"),
    }
    let mut changed = files;
    let at = changed
        .iter()
        .position(|file| file.path == BIG_BIN)
        .expect("the big file's listing");
    changed[at].chunk_sha256[0][0] ^= 1;
    let actual = encode_chunked_files(&changed)
        .unwrap_or_else(|refusal| panic!("the changed chunked listing: {refusal}"));
    assert_ne!(actual.to_string(), claimed);
    let reason = Refusal::NameMismatch {
        actual,
        claimed: claimed.clone(),
    }
    .to_string();
    let key = fresh_signing_key();
    let requested: LabCid = claimed.parse().expect("the listing's printed lab CID");
    let record = sign_cid_record(&key, requested);
    let mut lane = StandInRuntime::new(
        [(claimed.clone(), stored)],
        vec![record],
        vec![did_of(&key)],
    );
    let mut shared = StandIn::new();
    register_listing(&mut shared, &claimed);
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": claimed }),
        &reason,
        "the changed chunked listing",
    );
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "the changed chunked listing adds no grant"
    );
}

#[test]
fn standin_refuses_an_unsigned_or_unaccepted_photo_listing() {
    let entry = published_listing(photo_listing());
    assert_eq!(entry.0, PHOTO_STAND_IN_LAB_CID);
    let cid: LabCid = entry.0.parse().expect("the listing's printed lab CID");
    let cid_text = entry.0.clone();

    // (f) No record binds the CID.
    let key = fresh_signing_key();
    let mut lane = StandInRuntime::new([entry.clone()], vec![], vec![did_of(&key)]);
    let mut shared = StandIn::new();
    register_listing(&mut shared, &cid_text);
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": cid_text }),
        &format!("unsigned: no package record binds {cid_text}"),
        "(f) the unsigned photo listing",
    );
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "the unsigned photo listing adds no grant"
    );

    // (g1) A record signed by a key whose DID is not accepted, and (g2) the
    // same with an empty accepted list.
    let record = sign_cid_record(&fresh_signing_key(), cid);
    for (accepted, case) in [
        (
            vec![did_of(&fresh_signing_key())],
            "(g1) the unaccepted signer",
        ),
        (vec![], "(g2) the empty accepted list"),
    ] {
        let own = verify_cid_record(cid, &record, &accepted)
            .expect_err("the record is not accepted")
            .to_string();
        assert_eq!(
            own,
            format!("signer {} is not in the accepted list", record.signer_did)
        );
        let mut lane = StandInRuntime::new([entry.clone()], vec![record.clone()], accepted);
        let mut shared = StandIn::new();
        register_listing(&mut shared, &cid_text);
        assert_refused(
            &mut lane,
            &mut shared,
            &json!({ "cid": cid_text }),
            &own,
            case,
        );
        assert_eq!(
            grant_view(&lane, &shared),
            Vec::<Value>::new(),
            "{case}: the refused listing adds no grant"
        );
    }

    // (g3) One signature byte flipped, by an accepted signer.
    let key = fresh_signing_key();
    let mut flipped = sign_cid_record(&key, cid);
    flipped.signature[0] ^= 1;
    let accepted = vec![did_of(&key)];
    let own = verify_cid_record(cid, &flipped, &accepted)
        .expect_err("a flipped signature byte")
        .to_string();
    assert_eq!(
        own,
        format!(
            "signature by {} does not verify over {cid_text}",
            flipped.signer_did
        )
    );
    let mut lane = StandInRuntime::new([entry.clone()], vec![flipped], accepted);
    let mut shared = StandIn::new();
    register_listing(&mut shared, &cid_text);
    assert_refused(
        &mut lane,
        &mut shared,
        &json!({ "cid": cid_text }),
        &own,
        "(g3)",
    );

    // A correctly signed control launches: the refusals above come from the
    // record check, not from the listing input.
    let (mut lane, mut shared) = signed_listing(entry);
    assert_listing_journey(&mut lane, &mut shared, PHOTO_STAND_IN_LAB_CID);
}
