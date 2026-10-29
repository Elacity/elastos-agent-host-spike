//! Plan preview, owner approval and authorised execution (M1 check A15a).
//!
//! Every journey reaches the stand-in through its routes: `post_capsules`,
//! `finish_start`, `post_capability_request`, `post_capability_grant`,
//! `delete_capsule` and `post_capability_validate`. Setup calls `admit_resident`
//! only. No journey seeds a request or a grant.

#[path = "common/signed_bundle.rs"]
mod signed_bundle;

use agent_conformance::identity::sha256;
use agent_conformance::standin_runtime::{Caller, StandIn, Start};
use serde_json::{json, Value};
use signed_bundle::SignedBundle;

const RESOURCE: &str = "localhost://Public/plan-approval/a.txt";
const PLAN: &[u8] =
    br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"read"}]}"#;
/// The approved plan with one changed byte: another plan, another hash.
const CHANGED: &[u8] =
    br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"write"}]}"#;

/// Admit the fixture and launch it through `post_capsules` and `finish_start`.
fn running_agent(standin: &mut StandIn) -> (SignedBundle, String) {
    let bundle = SignedBundle::new();
    standin
        .admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )
        .expect("the stand-in admits the signed fixture");
    let launched = standin
        .post_capsules(Caller::Shell, &bundle.launch_body())
        .expect("the shell launches the admitted CID");
    let id = launched["id"]
        .as_str()
        .expect("the stand-in names the launch")
        .to_owned();
    standin.finish_start(&id).expect("the stand-in starts it");
    (bundle, id)
}

/// The agent asks for one plan through its own request route.
fn pending_request(standin: &mut StandIn, session_id: &str) -> String {
    let posted = standin
        .post_capability_request(
            Caller::Client { session_id },
            &json!({
                "resource": RESOURCE,
                "action": "read",
                "reason": "run the previewed plan",
                "plan": sha256(PLAN),
            }),
        )
        .expect("the agent's route stores one pending request");
    assert_eq!(posted["status"], "pending", "the request is pending");
    posted["request_id"].as_str().unwrap().to_owned()
}

/// The owner approves that plan through the grant route.
fn approve(standin: &mut StandIn, request_id: &str) {
    let granted = standin
        .post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": request_id,
                "duration": "once",
                "rationale": "owner approved",
            }),
        )
        .expect("the owner's grant route stores the once grant");
    assert_eq!(
        granted,
        json!({ "success": true }),
        "the grant carries no token"
    );
}

/// The agent's one live grant row, as the agent sees it.
fn live_rows(standin: &StandIn, session_id: &str) -> Value {
    standin
        .get_capability_list(Caller::Client { session_id }, None)
        .expect("the stand-in returns the client's live list")
}

/// The use body for `plan`, as `plan_approval::execute` sends it.
fn use_body(request_id: &str, plan: &[u8]) -> Value {
    json!({ "request_id": request_id, "plan_sha256": sha256(plan) })
}

#[test]
fn standin_plan_approval_spends_the_once_grant_once() {
    let mut standin = StandIn::new();
    let (_bundle, id) = running_agent(&mut standin);
    let request_id = pending_request(&mut standin, &id);

    // A bound grant is minted only by the owner's grant route.
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        json!([]),
        "the agent holds no grant before the owner approves"
    );
    approve(&mut standin, &request_id);
    let bound = live_rows(&standin, &id)["capabilities"].clone();
    assert_eq!(
        bound.as_array().map(Vec::len),
        Some(1),
        "the owner's approval leaves one live grant: {bound}"
    );

    let used = standin.post_capability_validate(
        Caller::Client { session_id: &id },
        &use_body(&request_id, PLAN),
    );
    assert_eq!(
        used,
        Ok(json!({ "valid": true })),
        "the approved plan's exact hash authorises one use"
    );
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        json!([]),
        "the once grant is spent after that use"
    );
    let again = standin.post_capability_validate(
        Caller::Client { session_id: &id },
        &use_body(&request_id, PLAN),
    );
    assert_eq!(
        again,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the same plan cannot spend the once grant twice"
    );
}

#[test]
fn standin_plan_change_is_refused_and_the_grant_stays_live() {
    let mut standin = StandIn::new();
    let (_bundle, id) = running_agent(&mut standin);
    let request_id = pending_request(&mut standin, &id);
    approve(&mut standin, &request_id);
    let bound = live_rows(&standin, &id)["capabilities"].clone();
    assert_eq!(
        bound.as_array().map(Vec::len),
        Some(1),
        "the victim grant exists before the changed plan is refused: {bound}"
    );

    let changed = standin.post_capability_validate(
        Caller::Client { session_id: &id },
        &use_body(&request_id, CHANGED),
    );
    assert_eq!(
        changed,
        Err((403, "grant is not bound to this plan".to_owned())),
        "a plan whose bytes changed after approval is refused"
    );
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        bound,
        "the refused use leaves the bound grant live, byte for byte"
    );

    // The grant is still the approved plan's to spend.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client { session_id: &id },
            &use_body(&request_id, PLAN),
        ),
        Ok(json!({ "valid": true })),
        "the approved plan still authorises its one use"
    );
}

#[test]
fn standin_agent_cannot_approve_its_own_plan() {
    let mut standin = StandIn::new();
    let (_bundle, id) = running_agent(&mut standin);
    let request_id = pending_request(&mut standin, &id);

    let self_approval = standin.post_capability_grant(
        Caller::Client { session_id: &id },
        &json!({ "request_id": request_id, "duration": "once" }),
    );
    assert_eq!(
        self_approval,
        Err((403, "This endpoint requires shell privileges".to_owned())),
        "the agent cannot approve its own plan"
    );
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        json!([]),
        "the refused self-approval mints no grant"
    );
    assert_eq!(
        standin.get_capability_request(Caller::Client { session_id: &id }, &request_id),
        Ok(json!({ "status": "pending" })),
        "the refused self-approval leaves the request pending"
    );
}

#[test]
fn standin_plan_preview_is_refused_when_it_is_dropped() {
    let mut standin = StandIn::new();
    let (_bundle, id) = running_agent(&mut standin);

    let plan_not_text = standin.post_capability_request(
        Caller::Client { session_id: &id },
        &json!({ "resource": RESOURCE, "action": "read", "plan": { "sha256": sha256(PLAN) } }),
    );
    assert_eq!(
        plan_not_text,
        Err((400, "request plan must be a string".to_owned())),
        "a plan preview the stand-in cannot honour is refused, not dropped"
    );
    let plan_silently_dropped = standin.post_capability_request(
        Caller::Client { session_id: &id },
        &json!({ "resource": RESOURCE, "action": "read", "plan_preview": sha256(PLAN) }),
    );
    assert_eq!(
        plan_silently_dropped,
        Err((400, "request body rejects plan_preview".to_owned())),
        "a plan key the route does not honour is refused, never dropped"
    );
    let wrong_hash = standin.post_capability_request(
        Caller::Client { session_id: &id },
        &json!({ "resource": RESOURCE, "action": "read", "plan": sha256(CHANGED) }),
    );
    assert_eq!(
        wrong_hash,
        Ok(json!({ "status": "pending", "request_id": "request-1" })),
        "a plan string is the hash of those bytes, so it is stored as given"
    );
    assert_eq!(
        standin.get_capability_requests(Caller::Shell, Some(&id)),
        Ok(json!({
            "requests": [{
                "request_id": "request-1",
                "session_id": id,
                "resource": RESOURCE,
                "action": "read",
                "reason": "",
                "status": "pending",
                "decision_reason": "",
                "settled_by": Value::Null,
            }],
        })),
        "the refused preview stores no record and the accepted one stores one"
    );
}

#[test]
fn standin_use_of_another_plans_grant_is_refused_and_both_grants_stay_live() {
    let mut standin = StandIn::new();
    let (_bundle, id) = running_agent(&mut standin);
    let request_a = pending_request(&mut standin, &id);
    let request_b = standin
        .post_capability_request(
            Caller::Client { session_id: &id },
            &json!({
                "resource": RESOURCE,
                "action": "read",
                "plan": sha256(CHANGED),
            }),
        )
        .expect("the agent's second request stores one pending request")["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(request_a, request_b, "two plans are two requests");

    // The owner approves plan A with grant G1 and plan B with grant G2.
    approve(&mut standin, &request_a);
    approve(&mut standin, &request_b);
    let both = live_rows(&standin, &id)["capabilities"].clone();
    assert_eq!(
        both.as_array().map(Vec::len),
        Some(2),
        "both bound grants are live: {both}"
    );

    // Executing plan A with grant G2 is refused and spends nothing.
    let wrong = standin.post_capability_validate(
        Caller::Client { session_id: &id },
        &use_body(&request_b, PLAN),
    );
    assert_eq!(
        wrong,
        Err((403, "grant is not bound to this plan".to_owned())),
        "grant G2 is bound to plan B, not plan A"
    );
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        both,
        "the refused wrong-grant use leaves both grants live, byte for byte"
    );

    // Executing plan A with grant G1 spends exactly G1.
    assert_eq!(
        standin.post_capability_validate(
            Caller::Client { session_id: &id },
            &use_body(&request_a, PLAN),
        ),
        Ok(json!({ "valid": true })),
        "grant G1 authorises plan A's one use"
    );
    assert_eq!(
        live_rows(&standin, &id)["capabilities"],
        json!([both[1]]),
        "the once grant G1 is spent and grant G2 is still live"
    );
}
