//! The one stand-in contract other lanes call.
//!
//! These tests call `StandIn`. They build no second grant list, no second
//! status map and no second JSON builder. They lock the RA-1 fields and the
//! RA-6 states from draft PR #309 at `513988ebd`. A PASS here gives the
//! Runtime no credit.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, Life, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::{SignedBundle, SHARED_NAME};
use std::collections::BTreeSet;

const LIVE_SCOPE: &str = "all_sessions_live";
const SHELL_REASON: &str = "This endpoint requires shell privileges";
const SHARED_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";
/// The manifest `name` of the second signed fixture.
const SECOND_NAME: &str = "agent-host-second";

fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("the stand-in returns an object")
        .keys()
        .cloned()
        .collect()
}

fn assert_keys(value: &Value, expected: &[&str], message: &str) {
    let expected: BTreeSet<String> = expected.iter().copied().map(str::to_owned).collect();
    assert_eq!(keys(value), expected, "{message}");
}

fn request_ids(body: &Value) -> BTreeSet<String> {
    body["capabilities"]
        .as_array()
        .expect("the stand-in returns a capability list")
        .iter()
        .map(|entry| {
            entry["request_id"]
                .as_str()
                .expect("the stand-in entry names request_id")
                .to_owned()
        })
        .collect()
}

#[test]
fn standin_matches_ra1_fields() {
    let mut standin = StandIn::new();

    let plain = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in returns the shell plain list");
    let query = standin
        .get_capability_list(Caller::Shell, Some(LIVE_SCOPE))
        .expect("the stand-in returns the shell scope list");
    for list in [&plain, &query] {
        assert_keys(
            list,
            &["capabilities", "scope"],
            "the stand-in did the work: the shell body carries scope and capabilities",
        );
        assert_eq!(
            list["scope"], LIVE_SCOPE,
            "the stand-in did the work: the shell body marks all_sessions_live"
        );
        assert_eq!(
            list["capabilities"],
            json!([]),
            "the stand-in did the work: the shell lists no grant before any seed"
        );
    }

    let empty_client = standin
        .get_capability_list(
            Caller::Client {
                session_id: "component-2",
            },
            None,
        )
        .expect("the stand-in returns the plain client list");
    assert_keys(
        &empty_client,
        &["capabilities"],
        "the stand-in did the work: the client body is the capability list",
    );
    assert_eq!(
        empty_client["capabilities"],
        json!([]),
        "the stand-in did the work: a client without a grant lists nothing"
    );

    let refused = standin.get_capability_list(
        Caller::Client {
            session_id: "component-1",
        },
        Some(LIVE_SCOPE),
    );
    assert!(
        matches!(&refused, Err((403, reason)) if reason == SHELL_REASON),
        "the stand-in did the work: a client scope list is refused: {refused:?}"
    );
    let unknown = standin.get_capability_list(Caller::Shell, Some("session"));
    assert!(
        matches!(
            &unknown,
            Err((400, reason)) if reason == "unknown capability list scope: session"
        ),
        "the stand-in did the work: an unknown scope is refused: {unknown:?}"
    );

    standin.seed_grant(
        "req-live",
        "component-1",
        SHARED_RESOURCE,
        "read",
        "session",
        0,
        Life::Live,
        false,
    );
    standin.seed_grant(
        "req-dead",
        "component-1",
        SHARED_RESOURCE,
        "read",
        "session",
        0,
        Life::Exhausted,
        false,
    );

    let shell = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in returns the seeded shell list");
    assert_eq!(
        request_ids(&shell),
        BTreeSet::from(["req-live".to_owned()]),
        "the stand-in did the work: the shell list leaves the exhausted grant out"
    );
    let entry = &shell["capabilities"][0];
    assert_keys(
        entry,
        &[
            "request_id",
            "session_id",
            "resource",
            "action",
            "duration",
            "granted_at",
        ],
        "the stand-in did the work: the shell entry carries the six RA-1 fields",
    );
    assert_eq!(
        entry["session_id"], "component-1",
        "the stand-in did the work: the shell entry names the grant's session"
    );
    assert_eq!(
        *entry,
        json!({
            "request_id": "req-live",
            "session_id": "component-1",
            "resource": SHARED_RESOURCE,
            "action": "read",
            "duration": "session",
            "granted_at": 0,
        }),
        "the stand-in did the work: the shell entry carries the seeded grant values"
    );

    let sibling = standin
        .get_capability_list(
            Caller::Client {
                session_id: "component-2",
            },
            None,
        )
        .expect("the stand-in returns the sibling client list");
    assert_eq!(
        sibling["capabilities"],
        json!([]),
        "the stand-in did the work: a sibling client lists no grant"
    );

    let own = standin
        .get_capability_list(
            Caller::Client {
                session_id: "component-1",
            },
            None,
        )
        .expect("the stand-in returns the client's own list");
    assert_eq!(
        request_ids(&own),
        BTreeSet::from(["req-live".to_owned()]),
        "the stand-in did the work: the client lists its own live grant only"
    );
    assert_keys(
        &own["capabilities"][0],
        &["request_id", "resource", "action", "duration", "granted_at"],
        "the stand-in did the work: the client entry carries the five RA-1 fields",
    );
}

#[test]
fn standin_settles_a_killed_agents_request() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    standin
        .admit_resident(
            shared.path(),
            &shared.signature(),
            shared.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits read-shared");
    let mut launched = Vec::new();
    for _ in 0..2 {
        let launch = standin
            .post_capsules(Caller::Shell, &shared.launch_body())
            .expect("the stand-in launches the admitted CID");
        let id = launch["id"]
            .as_str()
            .expect("the stand-in names each launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in finishes start");
        launched.push(id);
    }
    assert_eq!(
        launched,
        vec!["component-1".to_owned(), "component-2".to_owned()],
        "the stand-in numbers agent 1 and agent 2"
    );
    for (request_id, session_id) in [("request-1", "component-1"), ("request-2", "component-2")] {
        let posted = standin
            .post_capability_request(
                Caller::Client { session_id },
                &json!({
                    "resource": SHARED_RESOURCE,
                    "action": "read",
                    "reason": "read shared",
                }),
            )
            .expect("the agent's own route stores one pending request");
        assert_eq!(
            posted,
            json!({ "status": "pending", "request_id": request_id }),
            "the stand-in mints this request for this agent"
        );
    }
    standin
        .delete_capsule(
            Caller::Shell,
            "component-1",
            &json!({ "reason": "worker killed" }),
        )
        .expect("the stand-in stops agent 1 as a worker kill");

    let settlement = standin
        .get_capability_requests(Caller::Shell, Some("component-1"))
        .expect("the stand-in lists agent 1's records");
    assert_eq!(
        settlement,
        json!({
            "requests": [{
                "request_id": "request-1",
                "session_id": "component-1",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "read shared",
                "status": "denied",
                "decision_reason": "stopped: worker killed",
                "settled_by": "runtime",
            }],
        }),
        "the stand-in settles agent 1's pending request with the kill cause and the runtime as settler"
    );
    assert_eq!(
        standin.get_capability_request(
            Caller::Client {
                session_id: "component-1"
            },
            "request-1"
        ),
        Ok(json!({ "status": "denied", "reason": "stopped: worker killed" })),
        "the kill route answers agent 1's owner that its request settled"
    );
    assert_eq!(
        standin.get_capability_requests(Caller::Shell, Some("component-2")),
        Ok(json!({
            "requests": [{
                "request_id": "request-2",
                "session_id": "component-2",
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "read shared",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
            }],
        })),
        "the stand-in leaves agent 2's pending request untouched"
    );
    let capsules = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists both agents");
    let statuses = capsules["capsules"]
        .as_array()
        .expect("the stand-in returns a capsule list")
        .iter()
        .map(|capsule| {
            (
                capsule["id"].as_str().unwrap_or("").to_owned(),
                capsule["status"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            ("component-1".to_owned(), "stopped".to_owned()),
            ("component-2".to_owned(), "running".to_owned()),
        ],
        "the stand-in leaves agent 2 running when agent 1 is killed"
    );
    let retry = standin.post_capability_request(
        Caller::Client {
            session_id: "component-1",
        },
        &json!({
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "again",
        }),
    );
    assert_eq!(
        retry,
        Err((400, "instance is not live: stopped".to_owned())),
        "the stand-in refuses a silent retry that would reopen the settled request"
    );
    assert_eq!(
        standin.get_capability_requests(Caller::Shell, Some("component-1")),
        Ok(settlement),
        "the refused retry leaves the settled record and its settler"
    );
}

#[test]
fn standin_matches_ra6_states() {
    let mut standin = StandIn::new();

    let shared = SignedBundle::new();
    let cid = shared.cid();
    let refused = standin.post_capsules(Caller::Shell, &shared.launch_body());
    assert_eq!(
        refused,
        Err((
            404,
            format!("no bundle is admitted under {cid} in world resident-capsule")
        )),
        "the stand-in did the work: an unadmitted CID is refused with its own 404 reason"
    );

    let admitted = standin.admit_resident(
        shared.path(),
        &shared.signature(),
        shared.accepted(),
        Start::Ok,
    );
    assert_eq!(admitted, Ok(()), "the stand-in admits the signed bundle");

    let launched = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the admitted CID");
    assert_keys(
        &launched,
        &["id", "name", "session_id", "status"],
        "the stand-in did the work: the launch answer carries id, name, status and session_id",
    );
    assert_eq!(
        launched["status"], "starting",
        "the stand-in did the work: the launch answers starting before start returns"
    );
    assert_eq!(
        launched["session_id"], launched["id"],
        "the stand-in did the work: the launch answer names the instance's Bus session"
    );
    assert_eq!(
        launched["name"], SHARED_NAME,
        "the stand-in did the work: the launch answer carries the admitted name"
    );
    let id = launched["id"]
        .as_str()
        .expect("the stand-in names the launch")
        .to_owned();

    let listed = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the shell capsule list");
    assert_keys(
        &listed,
        &["capsules"],
        "the stand-in did the work: the capsule list body has one key",
    );
    let entry = &listed["capsules"][0];
    assert_keys(
        entry,
        &["cause", "id", "name", "session_id", "status"],
        "the stand-in did the work: the list entry carries id, name, status, session_id and cause",
    );
    assert_eq!(
        entry["status"], "starting",
        "the stand-in did the work: the list shows the instance starting"
    );
    assert_eq!(
        entry["cause"], "",
        "the stand-in did the work: a starting instance has an empty cause"
    );

    standin
        .finish_start(&id)
        .expect("the stand-in applies the admitted Start::Ok");
    let running = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the list after start");
    assert_eq!(
        running["capsules"][0]["status"], "running",
        "the stand-in did the work: start ok stores running"
    );
    assert_eq!(
        running["capsules"][0]["cause"], "",
        "the stand-in did the work: a running instance has an empty cause"
    );

    let mut failed = StandIn::new();
    failed
        .admit_resident(
            shared.path(),
            &shared.signature(),
            shared.accepted(),
            Start::Error("start refused".to_owned()),
        )
        .expect("the stand-in admits the signed bundle with a refused start");
    let refused_launch = failed
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the refused CID");
    failed
        .finish_start(
            refused_launch["id"]
                .as_str()
                .expect("the stand-in names the refused launch"),
        )
        .expect("the stand-in applies the refused start");
    let failed_list = failed
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the failed list");
    assert_eq!(
        failed_list["capsules"][0]["status"], "failed",
        "the stand-in did the work: a refused start stores failed"
    );
    assert_eq!(
        failed_list["capsules"][0]["cause"], "start refused",
        "the stand-in did the work: a refused start keeps its cause"
    );

    let stopped = standin
        .delete_capsule(Caller::Shell, &id, &json!({ "reason": "stop one" }))
        .expect("the stand-in stops the first instance");
    assert_eq!(
        stopped,
        Value::Null,
        "the stand-in did the work: the stop answers null"
    );
    let stopped_list = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the list after the stop");
    assert_eq!(
        stopped_list["capsules"][0]["status"], "stopped",
        "the stand-in did the work: the stop stores stopped"
    );
    assert_eq!(
        stopped_list["capsules"][0]["cause"], "stopped: stop one",
        "the stand-in did the work: the stop cause carries the reason"
    );

    let client = Caller::Client {
        session_id: "component-1",
    };
    let client_post = standin.post_capsules(client, &shared.launch_body());
    assert!(
        matches!(&client_post, Err((403, reason)) if reason == SHELL_REASON),
        "the stand-in did the work: a client launch is refused: {client_post:?}"
    );
    let client_list = standin.get_capsules(client);
    assert!(
        matches!(&client_list, Err((403, reason)) if reason == SHELL_REASON),
        "the stand-in did the work: a client list is refused: {client_list:?}"
    );
}
/// Two residents run through the routes. Each one asks for the shared
/// resource and gets a `once` grant from the shell. Cancelling the first
/// resident closes only its own request and its own grant; the second resident
/// keeps a live grant and completes its request.
#[test]
fn standin_cancelled_resident_leaves_the_second_resident_to_complete() {
    const SECOND_RESOURCE: &str = "localhost://Public/resident-instances/second.txt";
    const STOP_REASON: &str = "stopped: stop one";

    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    let second = SignedBundle::distinct(SECOND_NAME);
    for bundle in [&shared, &second] {
        declare_asks(
            bundle,
            &[
                (SHARED_RESOURCE, "read"),
                (SHARED_RESOURCE, "write"),
                (SECOND_RESOURCE, "write"),
            ],
        );
    }
    for bundle in [&shared, &second] {
        standin
            .admit_resident(
                bundle.path(),
                &bundle.signature(),
                bundle.accepted(),
                Start::Ok,
            )
            .expect("the stand-in admits both residents");
    }

    let mut started = Vec::new();
    for (bundle, name) in [(&shared, SHARED_NAME), (&second, SECOND_NAME)] {
        let launched = standin
            .post_capsules(Caller::Shell, &bundle.launch_body())
            .expect("the stand-in launches the admitted CID");
        assert_eq!(
            launched["name"], name,
            "the stand-in launches each admitted bundle under its own manifest name"
        );
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        standin
            .finish_start(&id)
            .expect("the stand-in applies the admitted Start::Ok");
        started.push(id);
    }
    let (first, second) = (started[0].as_str(), started[1].as_str());
    assert_ne!(first, second, "the stand-in names two sessions");

    let mut requested = Vec::new();
    for (session_id, action) in [(first, "read"), (second, "write")] {
        let pending = standin
            .post_capability_request(
                Caller::Client { session_id },
                &json!({
                    "resource": SHARED_RESOURCE,
                    "action": action,
                    "reason": "shared access",
                }),
            )
            .expect("the stand-in stores that resident's pending request");
        assert_eq!(
            pending["status"], "pending",
            "the stand-in answers pending for {session_id}"
        );
        let request_id = pending["request_id"]
            .as_str()
            .expect("the stand-in names the pending request")
            .to_owned();
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": "once" }),
            )
            .expect("the stand-in grants that resident's request once");
        requested.push(request_id);
    }
    let (first_request, second_request) = (requested[0].as_str(), requested[1].as_str());
    assert_ne!(
        first_request, second_request,
        "the stand-in names two granted requests"
    );

    let survivor_pending = {
        let pending = standin
            .post_capability_request(
                Caller::Client { session_id: second },
                &json!({
                    "resource": SECOND_RESOURCE,
                    "action": "write",
                    "reason": "second write",
                }),
            )
            .expect("the stand-in stores the surviving resident's second request");
        pending["request_id"]
            .as_str()
            .expect("the stand-in names the surviving resident's second request")
            .to_owned()
    };
    let first_pending = {
        let pending = standin
            .post_capability_request(
                Caller::Client { session_id: first },
                &json!({
                    "resource": SECOND_RESOURCE,
                    "action": "write",
                    "reason": "first write",
                }),
            )
            .expect("the stand-in stores the cancelled resident's pending request");
        pending["request_id"]
            .as_str()
            .expect("the stand-in names the cancelled resident's pending request")
            .to_owned()
    };
    assert_ne!(
        (first_pending.as_str(), survivor_pending.as_str()),
        (first_request, second_request),
        "the stand-in names the pending requests apart from the granted ones"
    );

    let both_live = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in lists both live grants before the cancel");
    assert_eq!(
        request_ids(&both_live),
        BTreeSet::from([first_request.to_owned(), second_request.to_owned()]),
        "the stand-in lists one live grant per resident before the cancel"
    );

    let stopped = standin
        .delete_capsule(Caller::Shell, first, &json!({ "reason": "stop one" }))
        .expect("the stand-in cancels the first resident mid-run");
    assert_eq!(
        stopped,
        Value::Null,
        "the stand-in did the work: the cancel answers null"
    );

    let cancelled_requests = standin
        .get_capability_requests(Caller::Shell, Some(first))
        .expect("the stand-in returns the cancelled resident's request records");
    assert_eq!(
        cancelled_requests["requests"],
        json!([{
            "request_id": first_request,
            "session_id": first,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "shared access",
            "status": "granted",
            "decision_reason": "Shell auto-grant",
            "settled_by": "shell",
        }, {
            "request_id": first_pending,
            "session_id": first,
            "resource": SECOND_RESOURCE,
            "action": "write",
            "reason": "first write",
            "status": "denied",
            "decision_reason": STOP_REASON,
            "settled_by": "runtime",
        }]),
        "the stand-in denies the cancelled resident's pending request and leaves its granted record alone"
    );
    let survivor_requests = standin
        .get_capability_requests(Caller::Shell, Some(second))
        .expect("the stand-in returns the surviving resident's request records");
    assert_eq!(
        survivor_requests["requests"],
        json!([{
            "request_id": second_request,
            "session_id": second,
            "resource": SHARED_RESOURCE,
            "action": "write",
            "reason": "shared access",
            "status": "granted",
            "decision_reason": "Shell auto-grant",
            "settled_by": "shell",
        }, {
            "request_id": survivor_pending,
            "session_id": second,
            "resource": SECOND_RESOURCE,
            "action": "write",
            "reason": "second write",
            "status": "pending",
            "decision_reason": "",
            "settled_by": Value::Null,
        }]),
        "the stand-in leaves the surviving resident's pending and granted records alone"
    );

    let after_cancel = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in lists the live grants after the cancel");
    assert_eq!(
        request_ids(&after_cancel),
        BTreeSet::from([second_request.to_owned()]),
        "the stand-in revokes only the cancelled resident's grant"
    );

    let survivor = Caller::Client { session_id: second };
    let survivor_view = standin
        .get_capability_list(survivor, None)
        .expect("the stand-in lists the surviving resident's own view");
    assert_eq!(
        request_ids(&survivor_view),
        BTreeSet::from([second_request.to_owned()]),
        "the stand-in keeps the surviving resident's grant in its own view"
    );
    let cancelled = Caller::Client { session_id: first };
    let cancelled_view = standin
        .get_capability_list(cancelled, None)
        .expect("the stand-in lists the cancelled resident's own view");
    assert_eq!(
        cancelled_view["capabilities"],
        json!([]),
        "the stand-in leaves no live grant in the cancelled resident's view"
    );

    standin
        .post_capability_validate(survivor, &json!({ "request_id": second_request }))
        .expect("the stand-in lets the surviving resident complete its request");
    let spent = standin
        .get_capability_list(survivor, None)
        .expect("the stand-in lists the surviving resident's view after use");
    assert_eq!(
        request_ids(&spent),
        BTreeSet::new(),
        "the stand-in lists the spent once grant no more"
    );

    let capsules = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in returns the capsule list");
    let listed = capsules["capsules"]
        .as_array()
        .expect("the stand-in returns capsules");
    assert_eq!(
        listed
            .iter()
            .find(|entry| entry["id"] == first)
            .map(|entry| (entry["status"].as_str(), entry["cause"].as_str())),
        Some((Some("stopped"), Some(STOP_REASON))),
        "the stand-in stores the cancelled resident stopped with its reason"
    );
    assert_eq!(
        listed
            .iter()
            .find(|entry| entry["id"] == second)
            .map(|entry| (entry["status"].as_str(), entry["cause"].as_str())),
        Some((Some("running"), Some(""))),
        "the stand-in leaves the surviving resident running"
    );
}

/// M1 check B2. The signed bundle declares one ask: a read of `ASK_RESOURCE`.
const ASK_RESOURCE: &str = "localhost://Users/self/.AppData/Agents/agent-host/tasks";
/// A path under `ASK_RESOURCE`. No ask names it.
const ASK_PATH: &str = "localhost://Users/self/.AppData/Agents/agent-host/tasks/demo/journal";
/// A path outside `ASK_RESOURCE`. No ask names it.
const OTHER_PATH: &str = "localhost://Users/self/.AppData/Agents/agent-host/other/journal";

/// Replaces the fixture's `asks.json` with exactly `asks`, before signing.
fn declare_asks(shared: &SignedBundle, asks: &[(&str, &str)]) {
    let listed = asks
        .iter()
        .map(|(resource, kind)| json!({ "kind": kind, "resource": resource }))
        .collect::<Vec<_>>();
    let file = json!({ "schema": "elastos.agent-host.asks/v1", "asks": listed });
    std::fs::write(
        shared.path().join("asks.json"),
        serde_json::to_vec_pretty(&file).expect("encode the fixture asks"),
    )
    .expect("write the fixture asks");
}

/// One admitted, launched and started guest, driven only through the routes.
fn launched_guest(standin: &mut StandIn, shared: &SignedBundle) -> String {
    standin
        .admit_resident(
            shared.path(),
            &shared.signature(),
            shared.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed bundle");
    let launched = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the admitted CID");
    let session = launched["session_id"]
        .as_str()
        .expect("the stand-in names the session")
        .to_owned();
    standin
        .finish_start(&session)
        .expect("the stand-in applies Start::Ok");
    session
}

fn request_records(standin: &StandIn, session: &str) -> Value {
    standin
        .get_capability_requests(Caller::Shell, Some(session))
        .expect("the stand-in lists the session's requests")["requests"]
        .clone()
}

#[test]
fn standin_refuses_a_request_its_signed_manifest_does_not_declare() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    declare_asks(&shared, &[(ASK_RESOURCE, "read")]);
    let session = launched_guest(&mut standin, &shared);
    let owner = Caller::Client {
        session_id: &session,
    };
    let body = |resource: &str, action: &str| json!({ "resource": resource, "action": action, "reason": "journey" });

    let declared = standin.post_capability_request(owner, &body(ASK_RESOURCE, "read"));
    assert_eq!(
        declared,
        Ok(json!({ "status": "pending", "request_id": "request-1" })),
        "the stand-in stores the one ask the signed manifest declares"
    );
    let stored = request_records(&standin, &session);
    assert_eq!(
        stored.as_array().map(Vec::len),
        Some(1),
        "the declared ask leaves the one stored request: {stored}"
    );

    for (resource, action) in [
        (OTHER_PATH, "read"),
        (ASK_PATH, "read"),
        (
            "localhost://Users/self/.AppData/Agents/agent-host/tasks/../secrets/key",
            "read",
        ),
        (ASK_RESOURCE, "write"),
        (ASK_PATH, "delete"),
        (ASK_PATH, "admin"),
    ] {
        let refused = standin.post_capability_request(owner, &body(resource, action));
        assert_eq!(
            refused,
            Err((
                403,
                format!("ask not declared in the signed manifest: {resource} {action}")
            )),
            "the stand-in refuses a request outside the signed asks ({resource} {action})"
        );
        assert_eq!(
            request_records(&standin, &session),
            stored,
            "a refused ask stores no request and leaves the stored one unchanged ({resource} {action})"
        );
    }
    assert_eq!(
        standin
            .get_capability_request(owner, "request-1")
            .expect("the owner reads its declared request"),
        json!({ "status": "pending" }),
        "the declared request is still the pending record its owner reads"
    );
}

#[test]
fn standin_refuses_to_launch_a_bundle_whose_signed_asks_changed() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    declare_asks(&shared, &[(ASK_RESOURCE, "read")]);
    let claimed = shared.cid();
    let admitted = standin.admit_resident(
        shared.path(),
        &shared.signature(),
        shared.accepted(),
        Start::Ok,
    );
    assert_eq!(
        admitted,
        Ok(()),
        "the stand-in admits the bundle whose signed asks declare the read"
    );
    let asks = shared.path().join("asks.json");
    let mut bytes = std::fs::read(&asks).expect("read asks.json");
    let at = bytes
        .windows(ASK_RESOURCE.len())
        .position(|window| window == ASK_RESOURCE.as_bytes())
        .expect("the signed asks name the declared resource");
    bytes[at] ^= 0x01;
    std::fs::write(&asks, &bytes).expect("change the declared resource in asks.json");
    let body = json!({ "cid": claimed });
    let launch = standin.post_capsules(Caller::Shell, &body);
    let expected = capsule_identity::Refusal::NameMismatch {
        actual: capsule_identity::lab_cid(shared.path())
            .expect("the walk names the bundle with the changed asks"),
        claimed: claimed.clone(),
    }
    .to_string();
    // Every changed byte leaves the bundle under a new lab CID, so the
    // signature's name check refuses the launch here (B1's reason). No
    // instance starts carrying the admitted asks, which is what the request
    // route's check needs; the launch never reaches the asks compare.
    assert!(
        matches!(&launch, Err((403, reason)) if reason == &expected),
        "the stand-in refuses changed bytes at launch with the B1 name-mismatch reason: {launch:?}"
    );
    assert_eq!(
        standin
            .get_capsules(Caller::Shell)
            .expect("the stand-in lists the capsules after the refused launch"),
        json!({ "capsules": [] }),
        "a refused launch lists nothing"
    );
    let undeclared = standin.post_capability_request(
        Caller::Client {
            session_id: "component-1",
        },
        &json!({ "resource": ASK_RESOURCE, "action": "read" }),
    );
    assert!(
        matches!(&undeclared, Err((400, reason)) if reason == "unknown instance: component-1"),
        "the refused launch started no guest that could ask: {undeclared:?}"
    );
}
