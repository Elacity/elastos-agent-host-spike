//! M1 check A6: each agent's grant is its own.
//!
//! Two agent bundles launch as two residents. Each asks for one capability
//! through `post_capability_request` and gets its own grant through
//! `post_capability_grant`; the grant route mints the pair `(run_id,
//! request_id)` that a hosted effect presents. The journey then presents
//! agent 1's pair as agent 2. The stand-in refuses it with one reason that
//! names agent 1, and agent 1's grant stays listed live and unspent.
//!
//! Every call enters through a stand-in route: `post_capsules`,
//! `finish_start`, `post_capability_request`, `post_capability_grant`,
//! `get_capability_requests`, `get_capability_list` and `admit_resident`.
//! Only the bundles this journey admits are set up for it; no grant, run pair
//! or request id comes from a literal.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::standin_runtime::{Caller, StandIn, Start};
use serde_json::json;
use signed_bundle::SignedBundle;
use std::sync::{Arc, Mutex};

const AGENT_A_NAME: &str = "agent-a";
const AGENT_B_NAME: &str = "agent-b";
const ASK_RESOURCE: &str = "localhost://Public/resident-instances/shared.txt";
/// The one shell live-grant scope `get_capability_list` accepts
/// (`standin-runtime/mod.rs:57`).
const SHELL_LIVE_SCOPE: &str = "all_sessions_live";

/// The pair a hosted effect presents, as the grant route returned it.
struct MintedRun {
    run_id: String,
    request_id: String,
}

/// Launches one admitted bundle through `post_capsules` and applies
/// `Start::Ok` through `finish_start`. Returns the instance id the launch
/// answered with.
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

/// The one request id `session` holds that is still pending, read from the
/// shell request list. A request the shell already settled is not that one.
fn listed_pending_request(standin: &StandIn, session: &str) -> String {
    let listed = standin
        .get_capability_requests(Caller::Shell, Some(session))
        .expect("the stand-in lists the session's requests");
    let pending = listed["requests"]
        .as_array()
        .expect("the request list is an array")
        .iter()
        .filter(|request| request["status"] == json!("pending"))
        .collect::<Vec<_>>();
    assert_eq!(
        pending.len(),
        1,
        "{session} holds exactly the one pending request this journey made"
    );
    assert_eq!(pending[0]["resource"], json!(ASK_RESOURCE));
    pending[0]["request_id"]
        .as_str()
        .expect("the listed request names its id")
        .to_owned()
}

/// One resident asks for `resource`, the shell grants it, and the journey
/// reads the minted pair back from the two route answers.
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
    let request_id = listed_pending_request(standin, session);
    let granted = standin
        .post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": request_id,
                "duration": "once",
                "rationale": "journey",
            }),
        )
        .expect("the shell grants the resident's request");
    // The grant route's answer stays exactly `{"success": true}`, so the
    // minted pair is read back from the grant's own read route. The agent
    // reads both halves and never chooses them.
    assert_eq!(
        granted,
        json!({ "success": true }),
        "the grant route answers success and no token"
    );
    let bound = standin
        .get_run_binding(owner, &request_id)
        .expect("the grant's own session reads back the pair the grant route minted");
    assert_eq!(
        bound["request_id"],
        json!(request_id),
        "the pair names the granted request"
    );
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

/// The whole A6 journey over `standin`. Its two agent bundles are already
/// admitted, so `check` reaches the guarded code only through the routes.
/// Returns the two launched instance ids at the first failed check's message.
fn check(standin: &Arc<Mutex<StandIn>>) -> Result<(String, String), String> {
    let mut locked = standin.lock().unwrap();
    let agent_1 = launch(&mut locked, &SignedBundle::distinct(AGENT_A_NAME));
    let agent_2 = launch(&mut locked, &SignedBundle::distinct(AGENT_B_NAME));
    if agent_1 == agent_2 {
        return Err(format!("both agents launched as one instance: {agent_1}"));
    }
    let victim = own_grant(&mut locked, &agent_1);

    // Agent 1's own pair works, so the pair under test is a genuine one.
    let own = locked.post_hosted_effect(
        Caller::Client {
            session_id: &agent_1,
        },
        "offer:journey",
        "read",
        &victim.run_id,
        &victim.request_id,
    );
    if own != Ok(json!({ "valid": true })) {
        return Err(format!("agent 1 cannot present its own pair: {own:?}"));
    }
    if listed_live(&locked, &victim.request_id) {
        return Err(format!(
            "agent 1's once grant {} stays live after its own use",
            victim.request_id
        ));
    }

    // A second grant for agent 1 is the victim of agent 2's presentation.
    let victim = own_grant(&mut locked, &agent_1);
    // Agent 2 cannot even read the pair: the read route keeps it to the
    // grant's own session.
    let peek = locked.get_run_binding(
        Caller::Client {
            session_id: &agent_2,
        },
        &victim.request_id,
    );
    if peek
        != Err((
            403u16,
            format!("wrong capsule: expected {agent_1}, got {agent_2}"),
        ))
    {
        return Err(format!("agent 2 can read agent 1's pair: {peek:?}"));
    }
    let presented = locked.post_hosted_effect(
        Caller::Client {
            session_id: &agent_2,
        },
        "offer:journey",
        "read",
        &victim.run_id,
        &victim.request_id,
    );
    let expected = Err((
        403u16,
        format!("wrong capsule: expected {agent_1}, got {agent_2}"),
    ));
    if presented != expected {
        return Err(format!(
            "agent 2's presentation of agent 1's pair is not refused with its own reason: {presented:?}"
        ));
    }
    if !listed_live(&locked, &victim.request_id) {
        return Err(format!(
            "agent 1's grant {} is not live after agent 2's refusal",
            victim.request_id
        ));
    }
    // The refusal spent nothing: agent 1's own pair still works, and its use
    // is the one that lets the once grant go.
    let after = locked.post_hosted_effect(
        Caller::Client {
            session_id: &agent_1,
        },
        "offer:journey",
        "read",
        &victim.run_id,
        &victim.request_id,
    );
    if after != Ok(json!({ "valid": true })) {
        return Err(format!(
            "agent 1's grant no longer works after agent 2's refusal: {after:?}"
        ));
    }
    if listed_live(&locked, &victim.request_id) {
        return Err(format!(
            "agent 1's once grant {} stays live after its own use",
            victim.request_id
        ));
    }
    Ok((agent_1, agent_2))
}

#[test]
fn a_hosted_effect_presents_only_a_pair_the_grant_route_minted() {
    let mut standin = StandIn::new();
    let bundles = [SignedBundle::distinct(AGENT_A_NAME)];
    for bundle in &bundles {
        standin
            .admit_resident(
                bundle.path(),
                &bundle.signature(),
                bundle.accepted(),
                Start::Ok,
            )
            .expect("the stand-in admits the signed agent bundle");
    }
    let mut locked = standin;
    let agent_1 = launch(&mut locked, &bundles[0]);
    let minted = own_grant(&mut locked, &agent_1);
    let owner = Caller::Client {
        session_id: &agent_1,
    };
    let published_id = "offer:journey";
    let effect = "read";
    // Everything else about the grant is valid: live, in this agent's session
    // and unused. Only the presented run id is one the route never minted.
    let unminted = format!("{}-not-minted", minted.run_id);
    let refused =
        locked.post_hosted_effect(owner, published_id, effect, &unminted, &minted.request_id);
    assert_eq!(
        refused,
        Err((
            403,
            format!(
                "effect run {unminted} is not bound to request {}",
                minted.request_id
            )
        )),
        "an unminted run id must be refused with the one pair reason"
    );
    // A request id the route never minted is refused the same way.
    let foreign_request = "request-never-minted";
    assert_eq!(
        locked.post_hosted_effect(owner, published_id, effect, &minted.run_id, foreign_request),
        Err((400, "unknown grant".to_owned())),
        "a pair whose request id was never minted names no grant"
    );
    assert!(
        listed_live(&locked, &minted.request_id),
        "each refusal must leave the minted grant live"
    );
    // The minted pair is the one that works, so the refusals came from the
    // pair check and not from something else missing.
    assert_eq!(
        locked.post_hosted_effect(
            owner,
            published_id,
            effect,
            &minted.run_id,
            &minted.request_id
        ),
        Ok(json!({ "valid": true })),
        "the minted pair must authorise the effect"
    );
}

#[test]
fn an_agent_cannot_present_another_agents_grant_pair() {
    let mut standin = StandIn::new();
    // The bundles stay alive: `post_capsules` walks their bytes on disk.
    let bundles = [
        SignedBundle::distinct(AGENT_A_NAME),
        SignedBundle::distinct(AGENT_B_NAME),
    ];
    for bundle in &bundles {
        standin
            .admit_resident(
                bundle.path(),
                &bundle.signature(),
                bundle.accepted(),
                Start::Ok,
            )
            .expect("the stand-in admits the signed agent bundle");
    }
    let standin = Arc::new(Mutex::new(standin));
    let (agent_1, agent_2) = check(&standin).expect("each agent's grant is its own");
    drop(bundles);
    assert_ne!(
        agent_1, agent_2,
        "the two agents are two resident instances"
    );
    // After the refused presentation and agent 1's own use, only agent 1 holds
    // requests and each record is settled `granted`.
    let locked = standin.lock().unwrap();
    let listed = locked
        .get_capability_requests(Caller::Shell, Some(&agent_1))
        .expect("the stand-in lists the agent's requests");
    let records = listed["requests"]
        .as_array()
        .expect("the request list is an array");
    assert_eq!(records.len(), 2, "agent 1 made exactly two requests");
    for record in records {
        assert_eq!(
            record["status"],
            json!("granted"),
            "the refusal changed no request record: {record}"
        );
        assert!(
            record["run_id"].is_null(),
            "the request record carries no run id; the grant route answer does: {record}"
        );
    }
    let agent_2_requests = locked
        .get_capability_requests(Caller::Shell, Some(&agent_2))
        .expect("the stand-in lists the agent's requests");
    assert_eq!(
        agent_2_requests,
        json!({ "requests": [] }),
        "agent 2 made no request and gained no grant"
    );
}
