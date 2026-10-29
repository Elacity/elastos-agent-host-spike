//! M1 check B1 through the lane's CID fixture entry point over the shared
//! stand-in: a launch names the bundle by its lab CID only, the lane's one
//! identity check runs before anything is launched, and the shared `StandIn`
//! in `lab/agent-conformance/standin-runtime/mod.rs` owns the instance, its
//! session id, its lifecycle and its grants. A launched instance is handed
//! only the `asks.json` bytes of the checked, signed bundle (M1 check B2, the
//! part with no schema and no parse). This is lab test code: it runs nothing,
//! and these tests say nothing about what the Runtime does.
mod common;

#[allow(dead_code)]
#[path = "../../agent-conformance/src/harness.rs"]
mod harness;

#[path = "../../agent-conformance/standin-runtime/mod.rs"]
mod standin_runtime;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use capsule_identity::{
    checked_bundle, sign_package_record, verify_checked_package_record, LabCid, PackageRecord,
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

/// The `agent-host` fixture assembled at `parent/name`, with `asks` as its
/// `asks.json`, so a test can publish a declaration of its own.
fn agent_host_with_asks(parent: &Path, name: &str, asks: &[u8]) -> PathBuf {
    let folder = parent.join(name);
    assemble_at(&AGENT_HOST, &folder);
    fs::write(folder.join("asks.json"), asks).expect("write asks.json");
    folder
}

/// The committed declaration with `edit` applied, as compact JSON bytes.
fn edited_asks(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(&read_fixture(&AGENT_HOST, "asks.json"))
        .expect("the committed asks.json is JSON");
    edit(&mut value);
    serde_json::to_vec(&value).expect("the edited declaration is JSON")
}

/// One lane over every folder in `folders`, each signed by its own fresh test
/// key whose DID is accepted, and one shared stand-in that registered each
/// folder once.
fn signed_bundles(folders: &[PathBuf]) -> (StandInRuntime, StandIn) {
    let mut entries = Vec::new();
    let mut records = Vec::new();
    let mut accepted = Vec::new();
    for folder in folders {
        let key = fresh_signing_key();
        records.push(sign(&key, folder));
        accepted.push(did_of(&key));
        entries.push(published(folder));
    }
    let lane = StandInRuntime::new(entries, records, accepted);
    let mut shared = StandIn::new();
    for folder in folders {
        register(&mut shared, folder);
    }
    (lane, shared)
}

/// The `(kind, resource)` pairs of `bytes`, read with the one JSON reader and
/// not with the parse under test, in file order.
fn pairs_of(bytes: &[u8]) -> Vec<(String, String)> {
    let value: Value = serde_json::from_slice(bytes).expect("the declaration is JSON");
    value["asks"]
        .as_array()
        .expect("an asks array")
        .iter()
        .map(|ask| {
            (
                ask["kind"].as_str().expect("a kind").to_owned(),
                ask["resource"].as_str().expect("a resource").to_owned(),
            )
        })
        .collect()
}

/// The launch of `cid` is refused with status 400 and exactly `reason`, the
/// shared list still holds `before` instances and the grant view stays empty.
fn assert_declaration_refused(
    lane: &mut StandInRuntime,
    shared: &mut StandIn,
    cid: &str,
    reason: &str,
    before: usize,
) {
    assert_eq!(
        launch_cid(lane, shared, cid),
        Err((400, reason.to_owned())),
        "{cid}: {reason}"
    );
    assert_eq!(
        listed_instances(shared).len(),
        before,
        "{cid}: a refused declaration leaves no new instance"
    );
    assert_eq!(
        grant_view(lane, shared),
        Vec::<Value>::new(),
        "{cid}: a refused declaration yields no grant"
    );
}

#[test]
fn standin_reads_declared_asks_from_the_signed_manifest() {
    let published = publish_agent_host();
    let parent = temp_dir();
    let malformed_bytes = b"{\"schema\": ".to_vec();
    let malformed_reason = format!(
        "asks declaration: {}",
        serde_json::from_slice::<Value>(&malformed_bytes).expect_err("the bytes are not JSON")
    );
    let variants: Vec<(&str, Vec<u8>, String)> = vec![
        (
            "schema-bad",
            edited_asks(|value| value["schema"] = json!("not-the-provisional-schema")),
            "asks declaration: schema is not-the-provisional-schema, not elastos.agent-host.asks/v1"
                .to_owned(),
        ),
        (
            "extra-root",
            edited_asks(|value| value["extra"] = json!(1)),
            "asks declaration: unknown field extra".to_owned(),
        ),
        (
            "extra-ask",
            edited_asks(|value| value["asks"][0]["extra"] = json!(1)),
            "asks declaration: unknown field extra".to_owned(),
        ),
        (
            "empty-kind",
            edited_asks(|value| value["asks"][0]["kind"] = json!("")),
            "asks declaration: an ask has an empty kind".to_owned(),
        ),
        (
            "empty-resource",
            edited_asks(|value| value["asks"][0]["resource"] = json!("")),
            "asks declaration: an ask has an empty resource".to_owned(),
        ),
        (
            "root-not-object",
            b"[]".to_vec(),
            "asks declaration: the root is not an object".to_owned(),
        ),
        (
            "missing-schema",
            edited_asks(|value| {
                value
                    .as_object_mut()
                    .expect("an object")
                    .remove("schema");
            }),
            "asks declaration: the root has no schema".to_owned(),
        ),
        (
            "missing-asks",
            edited_asks(|value| {
                value.as_object_mut().expect("an object").remove("asks");
            }),
            "asks declaration: the root has no asks".to_owned(),
        ),
        (
            "schema-not-string",
            edited_asks(|value| value["schema"] = json!([])),
            "asks declaration: schema is not a string".to_owned(),
        ),
        (
            "asks-not-array",
            edited_asks(|value| value["asks"] = json!({})),
            "asks declaration: asks is not an array".to_owned(),
        ),
        (
            "ask-not-object",
            edited_asks(|value| value["asks"][0] = json!(5)),
            "asks declaration: an ask is not an object".to_owned(),
        ),
        (
            "kind-not-string",
            edited_asks(|value| value["asks"][0]["kind"] = json!(5)),
            "asks declaration: a kind is not a string".to_owned(),
        ),
        (
            "resource-not-string",
            edited_asks(|value| value["asks"][0]["resource"] = json!(5)),
            "asks declaration: a resource is not a string".to_owned(),
        ),
        (
            "missing-kind",
            edited_asks(|value| {
                value["asks"][0]
                    .as_object_mut()
                    .expect("an object")
                    .remove("kind");
            }),
            "asks declaration: an ask has no kind".to_owned(),
        ),
        (
            "missing-resource",
            edited_asks(|value| {
                value["asks"][0]
                    .as_object_mut()
                    .expect("an object")
                    .remove("resource");
            }),
            "asks declaration: an ask has no resource".to_owned(),
        ),
        (
            "malformed",
            malformed_bytes,
            malformed_reason.clone(),
        ),
    ];
    let unknown_kind = agent_host_with_asks(
        parent.path(),
        "unknown-kind",
        &edited_asks(|value| value["asks"][0]["kind"] = json!("sing")),
    );
    let web_app = parent.path().join("web-app");
    assemble_at(&WEB_APP, &web_app);

    let folders: Vec<PathBuf> = variants
        .iter()
        .map(|(name, bytes, _)| agent_host_with_asks(parent.path(), name, bytes))
        .collect();
    let mut all = vec![published.folder.clone()];
    all.extend(folders.iter().cloned());
    all.push(unknown_kind.clone());
    all.push(web_app.clone());
    let (mut lane, mut shared) = signed_bundles(&all);

    let signed = read_fixture(&AGENT_HOST, "asks.json");
    let expected = pairs_of(&signed);
    assert_eq!(
        expected.first(),
        Some(&("read".to_owned(), "<principal>/".to_owned())),
        "the first committed ask"
    );

    let answer = launch_cid(&mut lane, &mut shared, AGENT_HOST_LAB_CID)
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(keys(&answer), ["id", "name", "session_id", "status"]);
    assert_eq!(answer["status"], "starting", "the shared launch's status");
    let session = answer["session_id"]
        .as_str()
        .expect("a session id")
        .to_owned();
    assert_eq!(
        lane.declared_asks_of(&session),
        Some(expected.clone()),
        "the journey parses the committed declaration in file order"
    );
    assert_eq!(
        lane.asks_of(&session),
        Some(signed.clone()),
        "the session keeps the committed asks bytes"
    );
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "a matching signature adds no grant"
    );

    // The read kind on disk becomes reed: (e) refuses with the name compare,
    // and the first session still declares the signed list.
    let stored = String::from_utf8(signed.clone()).expect("UTF-8 asks");
    let mutated = stored.replacen("\"read\"", "\"reed\"", 1);
    fs::write(published.folder.join("asks.json"), &mutated).expect("write asks.json");
    let now = named(&published.folder).to_string();
    assert_ne!(now, AGENT_HOST_LAB_CID);
    let compare = checked(&published.folder)
        .check_name(AGENT_HOST_LAB_CID)
        .expect_err("the bytes changed")
        .to_string();
    assert!(compare.contains(AGENT_HOST_LAB_CID) && compare.contains(&now));
    assert_declaration_refused(&mut lane, &mut shared, AGENT_HOST_LAB_CID, &compare, 1);
    assert_eq!(
        lane.declared_asks_of(&session),
        Some(expected.clone()),
        "the first session still declares read"
    );
    assert_eq!(
        lane.declared_asks_of(&session)
            .and_then(|asks| asks.first().cloned()),
        Some(("read".to_owned(), "<principal>/".to_owned()))
    );

    // No kind allow-list: an unknown kind launches and declares itself.
    let unknown_cid = named(&unknown_kind).to_string();
    let answer = launch_cid(&mut lane, &mut shared, &unknown_cid)
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(answer["status"], "starting");
    let unknown_session = answer["session_id"]
        .as_str()
        .expect("a session id")
        .to_owned();
    let mut declared_unknown = expected.clone();
    declared_unknown[0].0 = "sing".to_owned();
    assert_eq!(
        lane.declared_asks_of(&unknown_session),
        Some(declared_unknown),
        "an unknown kind is read as text"
    );

    // A bundle with no asks.json launches and declares nothing.
    let web_cid = named(&web_app).to_string();
    let answer = launch_cid(&mut lane, &mut shared, &web_cid)
        .unwrap_or_else(|(status, reason)| panic!("refused with {status}: {reason}"));
    assert_eq!(answer["status"], "starting");
    let web_session = answer["session_id"]
        .as_str()
        .expect("a session id")
        .to_owned();
    assert_eq!(lane.declared_asks_of(&web_session), None);
    assert_eq!(lane.asks_of(&web_session), None);
    assert_eq!(listed_instances(&shared).len(), 3);
    assert_eq!(
        lane.declared_asks_of("no-such-session"),
        None,
        "an unknown session declares nothing"
    );

    // Every declaration that does not meet the provisional schema refuses the
    // launch with its own reason, before the shared launch runs.
    for ((name, _, reason), folder) in variants.iter().zip(folders.iter()) {
        let cid = named(folder).to_string();
        assert_declaration_refused(&mut lane, &mut shared, &cid, reason, 3);
        assert_eq!(
            lane.declared_asks_of("no-such-session"),
            None,
            "{name}: no session appears for a refused declaration"
        );
    }
    assert_eq!(
        listed_instances(&shared).len(),
        3,
        "the three launches stayed"
    );
    assert_eq!(
        grant_view(&lane, &shared),
        Vec::<Value>::new(),
        "no launch adds a grant"
    );
}

#[test]
fn standin_declares_asks_once_and_from_the_store() {
    let common = include_str!("common/mod.rs");
    let parse = library_item(common, "pub fn provisional_asks(");
    assert_eq!(
        occurrences(parse, "serde_json::from_slice"),
        1,
        "the declaration holds one JSON parse"
    );
    let commit = library_item(common, "pub fn commit_launch(");
    assert_eq!(
        occurrences(commit, "provisional_asks"),
        1,
        "commit_launch runs the one declaration parse"
    );
    let anchored = "let (path, asks) = self.checked_launch(body).map_err(|reason| (400, reason))?;";
    let checked_at = commit.find(anchored).expect("the one checked launch line");
    let parse_at = commit
        .find("provisional_asks")
        .expect("the one declaration parse");
    let launch_at = commit
        .find("launch(&json!")
        .expect("the one shared launch call");
    assert!(
        checked_at < parse_at,
        "the declaration parses the bytes the checks returned"
    );
    assert!(
        parse_at < launch_at,
        "the declaration parses before the shared launch runs"
    );
    for head in ["pub fn declared_asks_of(", "pub fn asks_of("] {
        let body = library_item(common, head);
        assert_eq!(
            occurrences(body, "provisional_asks"),
            0,
            "{head} parses nothing"
        );
        assert_eq!(
            occurrences(body, "serde_json"),
            0,
            "{head} holds no JSON reader"
        );
    }
}

/// Every `.rs` file under `root`: the linked harness must not bring a second
/// copy of its storage rule into this crate.
fn rust_files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap_or_else(|error| panic!("{}: {error}", root.display())) {
        let entry = entry.expect("a directory entry");
        let path = entry.path();
        let kind = entry.file_type().expect("the entry's kind");
        if kind.is_dir() {
            rust_files(&path, out);
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "rs") {
            out.push(path);
        }
    }
}

fn occurrences(text: &str, needle: &str) -> usize {
    text.match_indices(needle).count()
}

#[test]
fn the_test_crate_links_the_one_harness() {
    let selected = Path::new("/tmp/ci-selected-home");
    let existed = selected.exists();
    assert_eq!(
        harness::data_dir(selected),
        Ok(selected.join("Library/Application Support/elastos")),
        "the linked harness resolves the selected Home's data directory"
    );
    assert_eq!(
        selected.exists(),
        existed,
        "resolving storage creates no directory"
    );

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(manifest.join("tests/stand_in.rs"))
        .expect("this test's own source in the crate");
    // Split here so this test's own needle text is not counted twice.
    let harness_link = concat!("../../agent-conformance/src/", "harness.rs");
    let standin_link = concat!("../../agent-conformance/standin-runtime/", "mod.rs");
    assert_eq!(
        occurrences(&source, harness_link),
        1,
        "the test crate links the one harness once"
    );
    assert_eq!(
        occurrences(&source, standin_link),
        1,
        "the test crate links the shared stand-in once"
    );

    let mut files = Vec::new();
    rust_files(manifest, &mut files);
    for file in &files {
        let text =
            fs::read_to_string(file).unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        for line in text.lines() {
            let line = line.trim();
            for prefix in [
                "fn data_dir(",
                "pub fn data_dir(",
                "pub(crate) fn data_dir(",
            ] {
                assert!(
                    !line.starts_with(prefix),
                    "{} holds a second storage rule: {line}",
                    file.display()
                );
            }
        }
    }
}
