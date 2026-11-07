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

/// Changes one payload byte of the signed bundle, so its bytes name another
/// lab CID and the admitted signature no longer covers it.
fn change_one_byte(bundle: &SignedBundle) {
    let asks = bundle.path().join("asks.json");
    let mut bytes = std::fs::read(&asks).expect("read asks.json");
    bytes[0] ^= 0x01;
    std::fs::write(&asks, &bytes).expect("flip one byte of asks.json");
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
                "plan": Value::Null,
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
                "plan": Value::Null,
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
fn standin_settles_a_running_workers_request_when_its_worker_exits() {
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
    let [agent_one, agent_two] = [&launched[0], &launched[1]];
    let body = |reason: &str| {
        json!({
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": reason,
        })
    };
    let posted = standin
        .post_capability_request(
            Caller::Client {
                session_id: agent_one,
            },
            &body("read shared"),
        )
        .expect("agent 1's own route stores one pending request");
    assert_eq!(
        posted,
        json!({ "status": "pending", "request_id": "request-1" }),
        "the stand-in mints one pending request for agent 1"
    );
    let unaffected = standin
        .post_capability_request(
            Caller::Client {
                session_id: agent_two,
            },
            &body("read shared again"),
        )
        .expect("agent 2's own route stores one pending request");
    assert_eq!(
        unaffected,
        json!({ "status": "pending", "request_id": "request-2" }),
        "the stand-in mints one pending request for agent 2"
    );
    let agent_two_pending = request_records(&standin, agent_two);
    assert_eq!(
        request_records(&standin, agent_one),
        json!([{
            "request_id": "request-1",
            "session_id": agent_one,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "pending",
            "decision_reason": "",
            "settled_by": Value::Null,
            "plan": Value::Null,
        }]),
        "agent 1's request outlives the guest call and is pending before the worker dies"
    );

    standin
        .worker_exited(agent_one)
        .expect("the stand-in records the dead worker of agent 1");

    assert_eq!(
        request_records(&standin, agent_one),
        json!([{
            "request_id": "request-1",
            "session_id": agent_one,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": "worker exited",
            "settled_by": "runtime",
            "plan": Value::Null,
        }]),
        "the dead worker settles agent 1's pending request as the runtime"
    );
    assert_eq!(
        standin.get_capability_request(
            Caller::Client {
                session_id: agent_one
            },
            "request-1"
        ),
        Ok(json!({ "status": "denied", "reason": "worker exited" })),
        "agent 1's owner reads its settled request through the request route"
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
                capsule["cause"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            (
                agent_one.to_owned(),
                "failed".to_owned(),
                "worker exited".to_owned()
            ),
            (agent_two.to_owned(), "running".to_owned(), String::new()),
        ],
        "the worker exit fails agent 1 only and leaves agent 2 running"
    );
    let refused = standin.post_capability_request(
        Caller::Client {
            session_id: agent_one,
        },
        &body("again"),
    );
    assert_eq!(
        refused,
        Err((400, "instance is not live: failed".to_owned())),
        "the stand-in refuses a silent retry for the dead worker"
    );
    assert_eq!(
        request_records(&standin, agent_one),
        json!([{
            "request_id": "request-1",
            "session_id": agent_one,
            "resource": SHARED_RESOURCE,
            "action": "read",
            "reason": "read shared",
            "status": "denied",
            "decision_reason": "worker exited",
            "settled_by": "runtime",
            "plan": Value::Null,
        }]),
        "the refused retry stores no request and leaves the settlement in place"
    );
    assert_eq!(
        request_records(&standin, agent_two),
        agent_two_pending,
        "agent 2's pending request is untouched by agent 1's worker exit"
    );
    let agent_two_owner = Caller::Client {
        session_id: agent_two,
    };
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": "request-2", "duration": "session" }),
        )
        .expect("the shell grants agent 2's pending request");
    assert_eq!(
        standin.post_capability_validate(agent_two_owner, &json!({ "request_id": "request-2" })),
        Ok(json!({ "valid": true })),
        "agent 2's grant is still usable after agent 1's worker died"
    );
}

#[test]
fn standin_refuses_a_worker_exit_for_an_unknown_or_ended_instance() {
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
    let launch = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the admitted CID");
    let running = launch["id"]
        .as_str()
        .expect("the stand-in names the launch")
        .to_owned();
    standin
        .finish_start(&running)
        .expect("the stand-in finishes start");
    standin
        .post_capability_request(
            Caller::Client {
                session_id: &running,
            },
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "read shared",
            }),
        )
        .expect("the running agent's own route stores one pending request");

    let running_before = request_records(&standin, &running);
    assert_eq!(
        standin.worker_exited("component-99"),
        Err((400, "unknown instance: component-99".to_owned())),
        "the stand-in refuses a worker exit for an id no launch minted"
    );
    assert_eq!(
        request_records(&standin, &running),
        running_before,
        "the refused unknown id leaves the running agent's pending request"
    );
    assert_eq!(
        standin.worker_exited(&running),
        Ok(()),
        "the stand-in accepts the one worker exit of a running instance"
    );
    let settled = request_records(&standin, &running);
    assert_eq!(
        settled[0]["status"],
        json!("denied"),
        "the accepted exit settles the running agent's pending request"
    );
    assert_eq!(
        standin.worker_exited(&running),
        Err((400, "instance is not live: failed".to_owned())),
        "the stand-in refuses a second worker exit for an instance it already ended"
    );
    let listed = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists the failed instance");
    assert_eq!(
        (
            listed["capsules"][0]["status"].clone(),
            listed["capsules"][0]["cause"].clone(),
        ),
        (json!("failed"), json!("worker exited")),
        "the refused second exit leaves the one phase and the one fixed cause"
    );
    assert_eq!(
        request_records(&standin, &running),
        settled,
        "the refused second exit leaves the settled record unchanged"
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
            "plan": Value::Null,
        }, {
            "request_id": first_pending,
            "session_id": first,
            "resource": SECOND_RESOURCE,
            "action": "write",
            "reason": "first write",
            "status": "denied",
            "decision_reason": STOP_REASON,
            "settled_by": "runtime",
            "plan": Value::Null,
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
            "plan": Value::Null,
        }, {
            "request_id": survivor_pending,
            "session_id": second,
            "resource": SECOND_RESOURCE,
            "action": "write",
            "reason": "second write",
            "status": "pending",
            "decision_reason": "",
            "settled_by": Value::Null,
            "plan": Value::Null,
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

/// M2 exit (b), lab half: every launch path refuses a tampered or unsigned
/// bundle at admission.
///
/// The shell admits a signed bundle, launches it, stops it through
/// `DELETE /api/capsules/:id`, changes one payload byte on disk, then
/// launches the same CID again and launches a second instance. Both launches
/// are refused with `capsule_identity`'s own name-mismatch text, because the
/// launch re-walks and re-verifies the bytes on disk now against the admitted
/// row. The capsule list gains nothing and the stopped instance stays exactly
/// as the stop left it.
#[test]
fn standin_tampered_bundle_is_refused_on_every_launch_path() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    let cid = shared.cid();
    standin
        .admit_resident(
            shared.path(),
            &shared.signature(),
            shared.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed bundle");

    let first = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the admitted CID");
    let first_id = first["id"]
        .as_str()
        .expect("the stand-in names the launch")
        .to_owned();
    standin
        .finish_start(&first_id)
        .expect("the stand-in applies the admitted Start::Ok");
    standin
        .delete_capsule(
            Caller::Shell,
            &first_id,
            &json!({ "reason": "swap the bundle" }),
        )
        .expect("the stand-in stops the first instance");

    change_one_byte(&shared);
    let stopped = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists before the refused launches");
    let before = stopped["capsules"]
        .as_array()
        .expect("the stand-in returns capsules")
        .clone();
    assert_eq!(
        before.len(),
        1,
        "the stand-in lists the one stopped instance before the refused launches"
    );
    assert_eq!(
        (before[0]["id"].as_str(), before[0]["status"].as_str()),
        (Some(first_id.as_str()), Some("stopped")),
        "the stop left the first instance stopped before the refused launches"
    );

    let tampered_cid = capsule_identity::checked_bundle(shared.path())
        .expect("the walk names the changed bundle")
        .cid();
    let tampered_cid = tampered_cid.to_string();
    assert_ne!(
        tampered_cid, cid,
        "the changed bundle's bytes name another lab CID, so the refusal comes from the bytes check"
    );
    let expected = capsule_identity::Refusal::NameMismatch {
        actual: tampered_cid.parse().expect("the walk prints a lab CID"),
        claimed: cid.clone(),
    }
    .to_string();

    // The launch body names the admitted CID itself: `launch_body` re-walks
    // the bundle, so it would name the changed bytes' CID, which no row holds.
    let admitted_launch = json!({ "cid": cid });
    for attempt in ["relaunch", "second instance"] {
        let refused = standin.post_capsules(Caller::Shell, &admitted_launch);
        assert_eq!(
            refused,
            Err((403, expected.clone())),
            "the {attempt} launch of the admitted CID refuses the changed bytes with the library's own text"
        );
        assert_eq!(
            standin
                .get_capsules(Caller::Shell)
                .expect("the stand-in lists after the refused launch"),
            json!({ "capsules": before }),
            "the refused {attempt} launch adds no instance and leaves the stopped one unchanged"
        );
    }
}

/// The negative control for the journey above: the same route with the same
/// launcher succeeds before the change and refuses an unadmitted CID with its
/// own 404. The change alone makes the relaunch refusal happen, so the journey
/// does not pass on a stand-in that refuses every launch.
#[test]
fn standin_untouched_bundle_relaunches_and_unadmitted_cid_is_refused() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    standin
        .admit_resident(
            shared.path(),
            &shared.signature(),
            shared.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed bundle");
    let first = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches the admitted CID before any change");
    let first_id = first["id"]
        .as_str()
        .expect("the stand-in names it")
        .to_owned();
    standin
        .delete_capsule(Caller::Shell, &first_id, &json!({ "reason": "relaunch" }))
        .expect("the stand-in stops the first instance");
    let relaunched = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the untouched bundle relaunches under its admitted CID");
    assert_eq!(
        relaunched["name"], SHARED_NAME,
        "the relaunch carries the admitted manifest name"
    );

    let other = SignedBundle::distinct(SECOND_NAME);
    let unadmitted = standin.post_capsules(Caller::Shell, &other.launch_body());
    assert_eq!(
        unadmitted,
        Err((
            404,
            format!(
                "no bundle is admitted under {} in world resident-capsule",
                other.cid()
            )
        )),
        "an unadmitted CID is refused with its own 404, not the tampered reason"
    );
}

/// M2 exit (b): a content capsule opens by CID as content and never runs as
/// code. The stand-in has no admission route, so this test drives the content
/// refusal at the `admit_resident` seam, then drives the launch route and gets
/// its own 404 for the unadmitted CID. The victim is a real app bundle with a
/// real launch, request and grant that must stay as it was.
#[test]
fn standin_refuses_a_content_bundle_at_the_admission_seam() {
    let mut standin = StandIn::new();
    let app = SignedBundle::new();
    standin
        .admit_resident(app.path(), &app.signature(), app.accepted(), Start::Ok)
        .expect("the stand-in admits the app bundle");
    let launched = standin
        .post_capsules(Caller::Shell, &app.launch_body())
        .expect("the stand-in launches the app bundle");
    let session_id = launched["session_id"]
        .as_str()
        .expect("the stand-in names the app session")
        .to_owned();
    standin
        .finish_start(&session_id)
        .expect("the stand-in finishes the app start");
    let requested = standin
        .post_capability_request(
            Caller::Client {
                session_id: &session_id,
            },
            &json!({ "resource": SHARED_RESOURCE, "action": "read", "reason": "read shared" }),
        )
        .expect("the app asks for one grant");
    let request_id = requested["request_id"]
        .as_str()
        .expect("the stand-in mints the app request")
        .to_owned();
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": request_id, "duration": "session" }),
        )
        .expect("the shell grants the app request");
    let before = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists the app instance");
    let grants_before = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in lists the app grant");

    let content = SignedBundle::content();
    assert_ne!(content.cid(), app.cid(), "the two bundles differ");
    let content_cid = content.cid();
    let path = content.path();
    let signature = content.signature();
    let accepted = content.accepted();
    let refused = standin.admit_resident(path, &signature, accepted, Start::Ok);
    match &refused {
        Err((status, reason)) => {
            assert_eq!(*status, 403, "content is refused as forbidden: {reason}");
            assert_eq!(
                reason,
                &format!(
                    "bundle {content_cid} has role content: content opens by CID and never runs as code"
                ),
                "the stand-in gives the one content reason"
            );
        }
        Ok(()) => panic!("a content bundle must not be admitted"),
    }

    let after = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists the capsules after the refusal");
    assert_eq!(
        after, before,
        "the refused admission added no instance: the app instance is as it was"
    );
    let launch_body = json!({ "cid": content_cid });
    let unlaunched = standin.post_capsules(Caller::Shell, &launch_body);
    match &unlaunched {
        Err((status, reason)) => {
            assert_eq!(*status, 404, "no row names the content CID: {reason}");
            assert_eq!(
                reason,
                &format!("no bundle is admitted under {content_cid} in world resident-capsule"),
                "the stand-in gives its not-resident reason"
            );
        }
        Ok(body) => panic!("a content CID must not launch: {body}"),
    }
    let grants_after = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in lists the grants after the refusal");
    assert_eq!(
        grants_after, grants_before,
        "the refused admission and launch added no grant: the app grant is as it was"
    );
    let requests = standin
        .get_capability_requests(Caller::Shell, Some(&session_id))
        .expect("the stand-in lists the app requests");
    assert_eq!(
        requests["requests"].as_array().map(Vec::len),
        Some(1),
        "the refused admission and launch added no request: the app request stays"
    );
    assert_eq!(
        requests["requests"][0]["request_id"],
        json!(request_id),
        "the app request is the one request, still granted"
    );
    assert_eq!(
        requests["requests"][0]["status"],
        json!("granted"),
        "the app grant stays: no admission or launch touched it"
    );
    let listed = after["capsules"]
        .as_array()
        .expect("the stand-in returns capsules");
    assert_eq!(
        listed.len(),
        1,
        "the only instance is the app's: the content bundle started none"
    );
    assert_eq!(listed[0]["id"], json!(session_id), "the app instance stays");
}

/// M1 check B2. Writes exactly `file` as the fixture's `asks.json`, before
/// signing, so the one walk reads the bytes the test meant.
fn declare_asks_file(shared: &SignedBundle, file: &Value) {
    std::fs::write(
        shared.path().join("asks.json"),
        serde_json::to_vec_pretty(file).expect("encode the fixture asks"),
    )
    .expect("write the fixture asks");
}

/// Refuses `shared` at `admit_resident` with status 400 and `reason`, and
/// proves the refusal stored no row: the capsule list and the capability
/// list are the same before and after, and the refused CID never launches.
fn assert_admission_refused(standin: &mut StandIn, shared: &SignedBundle, reason: &str) {
    let capsules_before = standin
        .get_capsules(Caller::Shell)
        .expect("the stand-in lists the capsules before");
    let grants_before = standin
        .get_capability_list(Caller::Shell, None)
        .expect("the stand-in lists the grants before");
    let refused = standin.admit_resident(
        shared.path(),
        &shared.signature(),
        shared.accepted(),
        Start::Ok,
    );
    match &refused {
        Err((status, said)) => {
            assert_eq!(*status, 400, "the refusal is a bad ask schema: {said}");
            assert_eq!(said, reason, "the stand-in gives the one reason");
        }
        Ok(()) => panic!("an invalid asks.json must not be admitted"),
    }
    assert_eq!(
        standin
            .get_capsules(Caller::Shell)
            .expect("the stand-in lists the capsules after"),
        capsules_before,
        "the refused admission added no instance"
    );
    assert_eq!(
        standin
            .get_capability_list(Caller::Shell, None)
            .expect("the stand-in lists the grants after"),
        grants_before,
        "the refused admission minted no grant"
    );
    assert_eq!(
        standin.post_capsules(Caller::Shell, &shared.launch_body()),
        Err((
            404,
            format!(
                "no bundle is admitted under {} in world resident-capsule",
                shared.cid()
            )
        )),
        "the refused bundle has no admitted row to launch"
    );
}

#[test]
fn standin_refuses_to_admit_a_bundle_whose_asks_do_not_follow_the_schema() {
    const BAD_ASKS: &str = "asks.json does not follow the provisional ask schema";
    let ask = json!({ "kind": "read", "resource": ASK_RESOURCE });

    let missing = SignedBundle::new();
    std::fs::remove_file(missing.path().join("asks.json")).expect("remove the asks file");
    assert_admission_refused(
        &mut StandIn::new(),
        &missing,
        "bundle declares no asks.json",
    );

    let schema = SignedBundle::new();
    declare_asks_file(
        &schema,
        &json!({ "schema": "elastos.agent-host.asks/v2", "asks": [ask] }),
    );
    assert_admission_refused(&mut StandIn::new(), &schema, BAD_ASKS);

    let resource = SignedBundle::new();
    declare_asks_file(
        &resource,
        &json!({
            "schema": "elastos.agent-host.asks/v1",
            "asks": [{ "kind": "read" }]
        }),
    );
    assert_admission_refused(&mut StandIn::new(), &resource, BAD_ASKS);

    let empty = SignedBundle::new();
    declare_asks_file(
        &empty,
        &json!({ "schema": "elastos.agent-host.asks/v1", "asks": [] }),
    );
    assert_admission_refused(&mut StandIn::new(), &empty, BAD_ASKS);
}

#[test]
fn standin_refuses_to_admit_a_bundle_whose_asks_carry_an_unknown_key() {
    let top = SignedBundle::new();
    declare_asks_file(
        &top,
        &json!({
            "schema": "elastos.agent-host.asks/v1",
            "asks": [{ "kind": "read", "resource": ASK_RESOURCE }],
            "extra": true
        }),
    );
    assert_admission_refused(
        &mut StandIn::new(),
        &top,
        "asks.json carries an unknown key: extra",
    );

    let inner = SignedBundle::new();
    declare_asks_file(
        &inner,
        &json!({
            "schema": "elastos.agent-host.asks/v1",
            "asks": [{ "note": "x", "kind": "read", "resource": ASK_RESOURCE }]
        }),
    );
    assert_admission_refused(
        &mut StandIn::new(),
        &inner,
        "asks.json carries an unknown key: note",
    );
}

/// M1 check A7: the one budget cap on the stand-in's admission path.
///
/// One guest, five routes and nothing else: `admit_resident` for setup, then
/// `post_capsules`, `finish_start`, `post_capability_request`,
/// `post_capability_grant` and `post_capability_validate`. The grant route
/// binds the grant on the shared ledger and stores the ledger's own handle,
/// so each admitted ask below is the ledger's `admit_ask` call with that
/// handle. No journey seeds a request or a grant and none reads the handle.
#[test]
fn standin_admission_admits_a_granted_ask_within_budget_and_refuses_one_above() {
    let mut standin = StandIn::new();
    let shared = SignedBundle::new();
    declare_asks(&shared, &[(SHARED_RESOURCE, "read")]);
    let session = launched_guest(&mut standin, &shared);
    let owner = Caller::Client {
        session_id: &session,
    };
    let requested = standin
        .post_capability_request(
            owner,
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "one read effect",
            }),
        )
        .expect("the agent's route stores one pending request");
    let request_id = requested["request_id"]
        .as_str()
        .expect("the stand-in names the request")
        .to_owned();
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": request_id, "duration": "session" }),
        )
        .expect("the shell grants the pending request");

    let live = |standin: &StandIn| {
        request_ids(
            &standin
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .expect("the stand-in shell live view"),
        )
    };
    let victim = BTreeSet::from([request_id.clone()]);

    // One above the cap is refused with the cap and the ask. That refusal is
    // the guarded check's: the grant is live, unspent and carries the handle
    // the grant route minted, so nothing before the cap compare refuses it.
    // The refused grant is the victim and stays live and unspent.
    let above = standin
        .post_capability_validate(owner, &json!({ "request_id": request_id, "amount": 4097 }));
    assert_eq!(
        above,
        Err((
            403,
            "budget ask exceeds the admission cap: asked 4097, cap 4096".to_owned()
        )),
        "the stand-in refuses an ask one above the cap with AdmitRefuse's reason"
    );
    assert_eq!(
        live(&standin),
        victim,
        "the refused ask leaves the granted effect live on the stand-in"
    );

    // The cap itself is admitted, so the refusal above is the boundary.
    let at_cap = standin
        .post_capability_validate(owner, &json!({ "request_id": request_id, "amount": 4096 }));
    assert_eq!(
        at_cap,
        Ok(json!({ "valid": true })),
        "the stand-in admits an ask at the cap"
    );
    // The 4096 above consumed the identity's budget, so a later ask on the
    // same grant is refused by the reserve and leaves the grant live.
    let later_ask = standin.post_capability_validate(owner, &json!({ "request_id": request_id }));
    assert_eq!(
        later_ask,
        Err((403, "reservation exceeds the ceiling".to_owned())),
        "a later ask on the same grant is refused once the budget is consumed"
    );
    assert_eq!(
        live(&standin),
        victim,
        "the refused later ask leaves the granted effect live"
    );

    // A malformed amount is refused against the same victim grant, before
    // the grant is read, so it spends nothing.
    for amount in [json!(-1), json!(1.5), json!("4096"), json!(null)] {
        let refused = standin.post_capability_validate(
            owner,
            &json!({ "request_id": request_id, "amount": amount }),
        );
        assert_eq!(
            refused,
            Err((
                400,
                "budget ask needs a non-negative integer amount".to_owned()
            )),
            "the stand-in refuses a malformed amount {amount} on a live granted request"
        );
    }
    assert_eq!(
        live(&standin),
        victim,
        "the malformed amounts leave the grant live and unspent"
    );

    // The budget decision runs before any spend, and the order is proved on
    // a second, `once` grant: an ask one above the cap is refused with the
    // cap text while the grant is still live and unspent, and an ask at the
    // cap is then admitted and spends it. The refusal is the guarded one:
    // the grant is live, unspent, owned by this caller and carries the handle
    // the grant route minted.
    let pending = standin
        .post_capability_request(
            owner,
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "one once effect",
            }),
        )
        .expect("the agent's route stores a second pending request");
    let once_id = pending["request_id"]
        .as_str()
        .expect("the stand-in names the request")
        .to_owned();
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": once_id, "duration": "once" }),
        )
        .expect("the shell grants the second request for one use");
    assert_eq!(
        live(&standin),
        BTreeSet::from([request_id.clone(), once_id.clone()]),
        "the shell live view lists the once grant live before its first use"
    );
    assert_eq!(
        standin.post_capability_validate(owner, &json!({ "request_id": once_id, "amount": 4097 })),
        Err((
            403,
            "budget ask exceeds the admission cap: asked 4097, cap 4096".to_owned()
        )),
        "the once grant's first ask one above the cap is refused with the cap text"
    );
    assert_eq!(
        live(&standin),
        BTreeSet::from([request_id.clone(), once_id.clone()]),
        "the refused ask leaves the once grant live and unspent"
    );
    // The session ceiling is filled by the cap use above, so the once grant's
    // own ask is refused by the reserve and spends nothing.
    assert_eq!(
        standin.post_capability_validate(owner, &json!({ "request_id": once_id, "amount": 4096 })),
        Err((403, "reservation exceeds the ceiling".to_owned())),
        "the once grant's ask is refused once the session ceiling is filled"
    );
    assert_eq!(
        live(&standin),
        BTreeSet::from([request_id.clone(), once_id.clone()]),
        "the refused ask leaves the once grant live and unspent"
    );

    // The spend order shows where nothing holds the ceiling: a second session
    // of the same bundle admits its once grant's ask at the cap and spends it.
    let fresh = standin
        .post_capsules(Caller::Shell, &shared.launch_body())
        .expect("the stand-in launches a second session of the admitted CID")["session_id"]
        .as_str()
        .expect("the stand-in names the session")
        .to_owned();
    standin
        .finish_start(&fresh)
        .expect("the stand-in applies Start::Ok");
    let fresh_owner = Caller::Client { session_id: &fresh };
    let fresh_id = standin
        .post_capability_request(
            fresh_owner,
            &json!({
                "resource": SHARED_RESOURCE,
                "action": "read",
                "reason": "one spend",
            }),
        )
        .expect("the second session stores one pending request")["request_id"]
        .as_str()
        .expect("the stand-in names the request")
        .to_owned();
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": fresh_id, "duration": "once" }),
        )
        .expect("the shell grants the second session's request");
    assert_eq!(
        standin.post_capability_validate(
            fresh_owner,
            &json!({ "request_id": fresh_id, "amount": 4096 })
        ),
        Ok(json!({ "valid": true })),
        "the once grant on a fresh session admits its ask at the cap"
    );
    assert!(
        !live(&standin).contains(&fresh_id),
        "the admitted ask spends the once grant"
    );
}
