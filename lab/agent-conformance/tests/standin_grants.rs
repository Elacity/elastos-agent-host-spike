//! M1 check A6 over the stand-in: two resident instances, each agent's own
//! grant set in the RA-1 live view, and the refusal when one agent presents
//! the other's grant.
//!
//! Every grant here comes from the routes: one `admit_resident` of the signed
//! fixture bundle, two `post_capsules` launches of that one admitted CID, then
//! each agent's own `post_capability_request` and the shell's
//! `post_capability_grant`. No test in this file calls `seed_grant`,
//! `seed_request`, `settle_pending`, `stop_one` or the request store. This is
//! stand-in lab evidence only; the Runtime books no A6 credit for it.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::SignedBundle;

const LIVE_SCOPE: &str = "all_sessions_live";
const RESOURCE_A: &str = "localhost://Public/resident-instances/a.txt";
const RESOURCE_B: &str = "localhost://Public/resident-instances/b.txt";

/// One launched resident with its one route grant.
struct Agent {
    session: String,
    request: String,
}

/// Admits the fixture bundle once and launches it `count` times, so the one
/// stand-in names one distinct session per agent.
fn launch_agents(standin: &mut StandIn, bundle: &SignedBundle, count: usize) -> Vec<String> {
    standin
        .admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the fixture bundle once");
    let mut sessions = Vec::new();
    for _ in 0..count {
        let launch = standin
            .post_capsules(Caller::Shell, &bundle.launch_body())
            .expect("the stand-in launches the admitted CID");
        let id = launch["id"]
            .as_str()
            .expect("the launch route names the session")
            .to_owned();
        assert_eq!(
            launch["session_id"], id,
            "the launch route names one session per instance"
        );
        standin
            .finish_start(&id)
            .expect("the stand-in applies the admitted Start::Ok");
        sessions.push(id);
    }
    assert_eq!(
        sessions.len(),
        count,
        "the launch route names {count} sessions"
    );
    for (index, left) in sessions.iter().enumerate() {
        for right in &sessions[index + 1..] {
            assert_ne!(left, right, "the launch route names two distinct sessions");
        }
    }
    sessions
}

/// One agent's pending request through its own route, then the shell's grant.
fn grant_one(standin: &mut StandIn, agent: &str, resource: &str, duration: &str) -> Agent {
    let posted = standin
        .post_capability_request(
            Caller::Client { session_id: agent },
            &json!({
                "resource": resource,
                "action": "read",
                "reason": "read my own file",
            }),
        )
        .expect("the agent's own route stores one pending request");
    assert_eq!(
        posted["status"], "pending",
        "the agent's own route stores a pending request: {posted}"
    );
    let request = posted["request_id"]
        .as_str()
        .expect("the request route names the pending request")
        .to_owned();
    assert!(
        request.starts_with("request-"),
        "the route's own grant id, never a caller key: {request}"
    );
    standin
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": request, "duration": duration }),
        )
        .expect("the shell grants that agent's request");
    Agent {
        session: agent.to_owned(),
        request,
    }
}

fn live_view(standin: &StandIn) -> Value {
    standin
        .get_capability_list(Caller::Shell, Some(LIVE_SCOPE))
        .expect("the stand-in answers the shell live view")
}

#[test]
fn standin_live_view_names_each_agents_own_grant_and_refuses_the_other() {
    let bundle = SignedBundle::new();
    let mut standin = StandIn::new();
    let sessions = launch_agents(&mut standin, &bundle, 2);
    let (agent_a, agent_b) = (sessions[0].clone(), sessions[1].clone());
    let a = grant_one(&mut standin, &agent_a, RESOURCE_A, "session");
    let b = grant_one(&mut standin, &agent_b, RESOURCE_B, "session");

    // The RA-1 live view lists each agent's own grant set, exactly.
    let view = live_view(&standin);
    assert_eq!(
        view,
        json!({
            "scope": LIVE_SCOPE,
            "capabilities": [
                {
                    "request_id": a.request,
                    "session_id": a.session,
                    "resource": RESOURCE_A,
                    "action": "read",
                    "duration": "session",
                    "granted_at": 0,
                },
                {
                    "request_id": b.request,
                    "session_id": b.session,
                    "resource": RESOURCE_B,
                    "action": "read",
                    "duration": "session",
                    "granted_at": 0,
                },
            ],
        }),
        "the live view names each agent's own grant under its own session"
    );

    // Each agent's plain client list holds its own grant and the other's
    // request id.
    for (own, other) in [(&a, &b), (&b, &a)] {
        let listed = standin
            .get_capability_list(
                Caller::Client {
                    session_id: &own.session,
                },
                None,
            )
            .expect("the stand-in answers the client list");
        assert_eq!(
            listed,
            json!({ "capabilities": [{
                "request_id": own.request,
                "resource": if own.session == a.session { RESOURCE_A } else { RESOURCE_B },
                "action": "read",
                "duration": "session",
                "granted_at": 0,
            }]}),
            "the client list holds that session's own grant only: {listed}"
        );
        assert!(
            !listed.to_string().contains(&other.request),
            "{} must not list {}'s grant: {listed}",
            own.session,
            other.session
        );
    }

    // Agent B presents agent A's grant id on the one use path. The victim is a
    // real live grant of a real live session, so the session tie is the only
    // refusal.
    let presented = standin.post_capability_validate(
        Caller::Client {
            session_id: &b.session,
        },
        &json!({ "request_id": a.request }),
    );
    assert_eq!(
        presented,
        Err((
            403,
            format!("wrong capsule: expected {}, got {}", a.session, b.session),
        )),
        "agent B presenting agent A's grant is refused with a reason that names both sessions"
    );

    // The refused presentation left agent A's grant live and unspent, and the
    // live view unchanged.
    assert_eq!(
        live_view(&standin),
        view,
        "the refused presentation leaves the live view unchanged"
    );
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &a.session,
            },
            &json!({ "request_id": a.request }),
        ),
        Ok(json!({ "valid": true })),
        "agent A still holds its own unspent grant after the refused presentation"
    );

    // Agent B's own grant still authorises agent B.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &b.session,
            },
            &json!({ "request_id": b.request }),
        ),
        Ok(json!({ "valid": true })),
        "agent B still holds its own grant"
    );
}

#[test]
fn standin_once_grant_is_consumed_by_its_owner_and_refused_on_reuse() {
    let bundle = SignedBundle::new();
    let mut standin = StandIn::new();
    let sessions = launch_agents(&mut standin, &bundle, 2);
    let (agent_a, agent_b) = (sessions[0].clone(), sessions[1].clone());
    let a = grant_one(&mut standin, &agent_a, RESOURCE_A, "once");
    let b = grant_one(&mut standin, &agent_b, RESOURCE_B, "session");
    assert_eq!(
        live_view(&standin)["capabilities"],
        json!([
            {
                "request_id": a.request,
                "session_id": a.session,
                "resource": RESOURCE_A,
                "action": "read",
                "duration": "once",
                "granted_at": 0,
            },
            {
                "request_id": b.request,
                "session_id": b.session,
                "resource": RESOURCE_B,
                "action": "read",
                "duration": "session",
                "granted_at": 0,
            },
        ]),
        "the live view lists the two route grants"
    );

    // Agent B's presentation of agent A's `once` grant is refused, and it does
    // not spend it.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &b.session,
            },
            &json!({ "request_id": a.request }),
        ),
        Err((
            403,
            format!("wrong capsule: expected {}, got {}", a.session, b.session),
        )),
        "the refused presentation of the once grant is refused by the session tie"
    );
    assert_eq!(
        live_view(&standin)["capabilities"][0],
        json!({
            "request_id": a.request,
            "session_id": a.session,
            "resource": RESOURCE_A,
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }),
        "the refused presentation leaves the once grant live"
    );

    // Agent A uses its own once grant: the one use path succeeds and spends it.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &a.session,
            },
            &json!({ "request_id": a.request }),
        ),
        Ok(json!({ "valid": true })),
        "agent A's own once grant authorises its one use"
    );
    assert_eq!(
        live_view(&standin)["capabilities"],
        json!([{
            "request_id": b.request,
            "session_id": b.session,
            "resource": RESOURCE_B,
            "action": "read",
            "duration": "session",
            "granted_at": 0,
        }]),
        "the spent once grant leaves the live view and the sibling grant stays"
    );
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &a.session,
            },
            &json!({ "request_id": a.request }),
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "agent A's reuse of its spent once grant is refused"
    );
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client {
                session_id: &b.session,
            },
            &json!({ "request_id": b.request }),
        ),
        Ok(json!({ "valid": true })),
        "the sibling's session grant still authorises its owner"
    );
}
