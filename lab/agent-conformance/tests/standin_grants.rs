//! M1 check A6: each agent's grant is its own.
//!
//! Two agent bundles launch as two residents through `post_capsules` and
//! `finish_start`. Each asks for one capability through
//! `post_capability_request` and receives its own grant through
//! `post_capability_grant`; the grant route mints the pair `(run_id,
//! request_id)` that a hosted effect presents. The journey presents agent A's
//! pair as agent B: the stand-in refuses it with the one reason that names
//! both sessions, agent A's grant stays listed live, and only agent A's own
//! use spends it. A pair the route never minted is refused the same way.
//!
//! Every call enters through a stand-in route; no grant, run pair or request
//! id comes from a literal.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, Life, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::SignedBundle;

const ASK_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";
/// The one shell live-grant scope `get_capability_list` accepts
/// (`standin-runtime/mod.rs:57`).
const SHELL_LIVE_SCOPE: &str = "all_sessions_live";
/// The offer and effect every hosted effect presents.
const OFFER: &str = "offer:journey";
const EFFECT: &str = "read";

/// The pair a hosted effect presents, as its own session read it back.
struct MintedRun {
    run_id: String,
    request_id: String,
}

/// Launches one admitted bundle through `post_capsules` and applies
/// `Start::Ok` through `finish_start`. Returns the instance id the launch
/// answered with, so no test assumes one.
fn launch(standin: &mut StandIn, bundle: &SignedBundle) -> String {
    let launched = standin
        .post_capsules(Caller::Shell, &bundle.launch_body())
        .expect("the stand-in launches the admitted CID");
    let id = launched["id"]
        .as_str()
        .expect("the launch answer names the instance")
        .to_owned();
    standin
        .finish_start(&id)
        .expect("the stand-in applies Start::Ok");
    id
}

/// One resident asks for `ASK_RESOURCE`, the shell grants it, and the grant's
/// own session reads the minted pair back from the route answer.
fn own_grant(standin: &mut StandIn, session: &str) -> MintedRun {
    let owner = Caller::Client {
        session_id: session,
    };
    standin
        .post_capability_request(
            owner,
            &json!({ "resource": ASK_RESOURCE, "action": "read", "reason": "journey" }),
        )
        .expect("the resident stores its one request");
    let listed = standin
        .get_capability_requests(Caller::Shell, Some(session))
        .expect("the stand-in lists the session's requests");
    let pending = listed["requests"]
        .as_array()
        .expect("the request list is an array")
        .iter()
        .filter(|request| request["status"] == json!("pending"))
        .map(|request| {
            request["request_id"]
                .as_str()
                .expect("the request names its id")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        pending.len(),
        1,
        "{session} holds exactly one pending request"
    );
    let request_id = pending[0].to_string();
    // The grant route's answer stays exactly `{"success": true}`, so the
    // agent reads the pair back from its own grant read route.
    assert_eq!(
        standin
            .post_capability_grant(
                Caller::Shell,
                &json!({ "request_id": request_id, "duration": "once", "rationale": "journey" }),
            )
            .expect("the shell grants the resident's request"),
        json!({ "success": true }),
        "the grant route answers success and no token"
    );
    let bound = standin
        .get_run_binding(owner, &request_id)
        .expect("the grant's own session reads back the pair the grant route minted");
    assert_eq!(bound["request_id"], json!(request_id));
    let run_id = bound["run_id"]
        .as_str()
        .expect("the read returns the run id the grant route minted")
        .to_owned();
    assert_ne!(
        run_id, request_id,
        "the minted run id is the route's own value, not the request id the agent chose"
    );
    MintedRun { run_id, request_id }
}

/// One hosted effect presented by `session`, through the effect route.
fn present(
    standin: &mut StandIn,
    session: &str,
    run_id: &str,
    request_id: &str,
) -> Result<Value, (u16, String)> {
    standin.post_hosted_effect(
        Caller::Client {
            session_id: session,
        },
        OFFER,
        EFFECT,
        run_id,
        request_id,
    )
}

/// True when the shell live view lists one grant for `request_id`.
fn listed_live(standin: &StandIn, request_id: &str) -> bool {
    let view = standin
        .get_capability_list(Caller::Shell, Some(SHELL_LIVE_SCOPE))
        .expect("the stand-in lists the shell's live grants");
    view["capabilities"]
        .as_array()
        .expect("the live view lists capabilities")
        .iter()
        .any(|entry| entry["request_id"] == json!(request_id))
}

/// Admits one signed agent bundle through `admit_resident`. The bundle stays
/// alive: `post_capsules` walks its bytes on disk.
fn admit(standin: &mut StandIn, bundle: &SignedBundle) {
    standin
        .admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed agent bundle");
}

#[test]
fn an_agent_cannot_present_another_agents_grant_pair() {
    let mut standin = StandIn::new();
    let bundles = [
        SignedBundle::distinct("agent-a"),
        SignedBundle::distinct("agent-b"),
    ];
    for bundle in &bundles {
        admit(&mut standin, bundle);
    }
    let agent_a = launch(&mut standin, &bundles[0]);
    let agent_b = launch(&mut standin, &bundles[1]);
    assert_ne!(
        agent_a, agent_b,
        "the two agents are two resident instances"
    );
    let victim = own_grant(&mut standin, &agent_a);
    // A seeded grant stores no run pair, so an empty presented run id must
    // find it and still be refused, live afterwards. The id is a journey
    // literal because no route seeds one.
    standin.seed_grant(
        "request-seeded",
        &agent_a,
        ASK_RESOURCE,
        "read",
        "once",
        0,
        Life::Live,
        false,
    );
    let refused = (
        403u16,
        format!("wrong capsule: expected {agent_a}, got {agent_b}"),
    );
    let reason = |run_id: &str, request_id: &str| {
        (
            403u16,
            format!("effect run {run_id} is not bound to request {request_id}"),
        )
    };

    // A pair the route never minted is refused with the one pair reason, and
    // agent A's grant stays live. Its request id still exists and is live, so
    // only the run half can refuse.
    assert_eq!(
        present(
            &mut standin,
            &agent_a,
            "run-never-minted",
            &victim.request_id
        ),
        Err(reason("run-never-minted", &victim.request_id)),
        "an unminted run id is refused with the one pair reason"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "an unminted pair spends nothing"
    );

    // An empty presented run id is a pair nothing minted, even for the grant's
    // own session: the stand-in refuses it and spends nothing (a seeded grant
    // stores an empty run id, so no presented pair reaches it).
    assert_eq!(
        present(&mut standin, &agent_a, "", &victim.request_id),
        Err(reason("", &victim.request_id)),
        "an empty presented run id is refused with the one pair reason"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "an empty pair leaves agent A's grant live and unspent"
    );
    assert_eq!(
        present(&mut standin, &agent_a, "", "request-seeded"),
        Err(reason("", "request-seeded")),
        "a seeded grant is refused an empty pair with the one pair reason"
    );
    assert!(
        listed_live(&standin, "request-seeded"),
        "the seeded grant stays live and unspent"
    );

    // Agent B cannot read agent A's pair, and cannot present it.
    assert_eq!(
        standin.get_run_binding(
            Caller::Client {
                session_id: &agent_b
            },
            &victim.request_id
        ),
        Err(refused.clone()),
        "agent B reads no pair it does not own"
    );
    assert_eq!(
        present(&mut standin, &agent_b, &victim.run_id, &victim.request_id),
        Err(refused),
        "agent B's presentation of agent A's pair is refused, naming both sessions"
    );
    assert!(
        listed_live(&standin, &victim.request_id),
        "agent A's grant {} stays live after agent B's refusal",
        victim.request_id
    );

    // The refusal spent nothing: agent A's own pair still works, and that one
    // use is what spends the `once` grant.
    assert_eq!(
        present(&mut standin, &agent_a, &victim.run_id, &victim.request_id),
        Ok(json!({ "valid": true })),
        "agent A's own pair still authorises the effect after agent B's refusal"
    );
    assert!(
        !listed_live(&standin, &victim.request_id),
        "agent A's own use spends its once grant"
    );
    assert_eq!(
        standin
            .get_capability_requests(Caller::Shell, Some(&agent_b))
            .expect("the stand-in lists agent B's requests"),
        json!({ "requests": [] }),
        "agent B made no request and gained no grant"
    );
}
