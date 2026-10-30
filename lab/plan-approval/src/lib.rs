#![forbid(unsafe_code)]

//! Plan preview, owner approval and authorised execution (M1 check A15a).
//!
//! A proposal carries no authority. `preview` hashes the canonical plan bytes
//! and writes nothing. `approve` asks the stand-in's owner-only grant route
//! once, naming the plan hash the owner saw with the request; that route mints
//! the binding from the hash it approved only when it equals the hash the
//! agent requested, and refuses a mismatch. `execute` asks the stand-in's
//! validate route for that plan. A grant bound to another plan is refused
//! there and spends nothing.

use agent_conformance::standin_runtime::{Caller, StandIn};
use serde_json::{json, Value};

/// One plan preview. The hash names the exact fixture bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preview {
    pub plan: Vec<u8>,
    pub sha256: String,
}

/// Return the plan bytes and their SHA-256. The stand-in stays untouched.
pub fn preview(stand_in: &mut StandIn, plan: &[u8]) -> Preview {
    let _ = stand_in;
    Preview {
        plan: plan.to_vec(),
        sha256: plan_sha256(plan),
    }
}

/// The one plan hash. `execute` uses it for the plan it runs.
///
/// The hash is SHA-256 over the exact bytes given (lowercase hex, 64
/// characters). It does not canonicalise: reordered keys, different whitespace,
/// or more than one changed byte each give a different hash, because the bytes
/// are the plan. There is no text form of a plan to parse.
pub fn plan_sha256(plan: &[u8]) -> String {
    agent_conformance::identity::sha256(plan)
}

/// The owner approves one pending request through `POST /api/capability/grant`.
///
/// `plan_sha256` is the plan hash the owner saw with the request, the value the
/// shell's request view shows in `plan`. The grant route mints the binding from
/// that hash only when it equals the hash the agent requested; a missing or
/// different hash is refused and the request stays pending.
pub fn approve(
    stand_in: &mut StandIn,
    request_id: &str,
    plan_sha256: &str,
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_grant(
        Caller::Shell,
        &json!({
            "request_id": request_id,
            "duration": "once",
            "rationale": "owner approved",
            "plan_sha256": plan_sha256,
        }),
    )
}

/// The owner denies one shown step through `POST /api/capability/deny`.
///
/// The call is the shell's refusal of the pending request the owner saw. It
/// stores `denied` with `shell` as settler and mints no grant, so a denied
/// step is not live and cannot be granted later. The reason is the one this
/// helper sends, `deny the shown plan`.
pub fn deny_shown_plan(stand_in: &mut StandIn, request_id: &str) -> Result<Value, (u16, String)> {
    stand_in.post_capability_deny(
        Caller::Shell,
        &json!({
            "request_id": request_id,
            "reason": "deny the shown plan",
        }),
    )
}

/// The agent runs one plan through `POST /api/capability/validate`.
///
/// The agent asks for the hash of the bytes it holds now, so a plan that
/// changed after approval is refused by the stand-in with status 403 and
/// `grant is not bound to this plan`, and a `once` grant stays `Live`.
pub fn execute(
    stand_in: &mut StandIn,
    session_id: &str,
    request_id: &str,
    plan: &[u8],
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_validate(
        Caller::Client { session_id },
        &json!({ "request_id": request_id, "plan_sha256": plan_sha256(plan) }),
    )
}

/// Moves the stand-in's clock to `secs` and lets the stand-in expire due
/// pending requests. It calls `set_instant` and no other `StandIn` method.
///
/// A pending shown step whose age is at least 300 seconds becomes `expired`
/// with `Request timed out` and `runtime` as settler, so it is not a live
/// grant and cannot be granted later. A granted record stays granted and its
/// `once` grant stays live, because that grant's own expiry is later. The
/// helper takes no request id and no plan.
pub fn age_shown_plan(stand_in: &mut StandIn, secs: u64) {
    stand_in.set_instant(secs);
}

/// The owner stops one shown session through `DELETE /api/capsules/:id`.
///
/// It calls `delete_capsule` as `Caller::Shell` with that id and the one body
/// key `reason`, `stop the shown session`, and returns that result. The call
/// is the cancel settlement the design names: "an explicit interrupt or
/// cancel operation that reports its settlement". The stand-in stores
/// `stopped` with the cause `stopped: stop the shown session`, denies that
/// session's pending requests with `runtime` as settler, and revokes that
/// session's `Live` grants. A granted record stays `granted`. Another
/// session's pending request stays pending. Ok is JSON null. The helper takes
/// no plan and no approved flag.
pub fn stop_shown_session(
    stand_in: &mut StandIn,
    session_id: &str,
) -> Result<Value, (u16, String)> {
    stand_in.delete_capsule(
        Caller::Shell,
        session_id,
        &json!({ "reason": "stop the shown session" }),
    )
}

#[cfg(test)]
mod fixtures {
    pub const PLAN_A: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"read"}]}"#;
    pub const PLAN_B: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/b.txt","action":"read"}]}"#;
    pub const UNCHANGED: &str = "the preview returned the plan bytes, the hash is sha256 of those bytes, and the live grants and the capsule list are unchanged";
}

#[cfg(test)]
#[test]
fn preview_makes_no_effect() {
    use agent_conformance::identity::sha256;
    use agent_conformance::standin_runtime::{Caller, Life};
    use fixtures::{PLAN_A, PLAN_B, UNCHANGED};

    assert_ne!(sha256(PLAN_A), sha256(PLAN_B), "fixtures differ");

    let mut stand_in = StandIn::new();
    let grants_before = stand_in
        .get_capability_list(Caller::Shell, Some("all_sessions_live"))
        .expect("fresh shell live list");
    let capsules_before = stand_in
        .get_capsules(Caller::Shell)
        .expect("fresh shell capsules");

    let mut previews = Vec::new();
    previews.push(preview(&mut stand_in, PLAN_A));
    previews.push(preview(&mut stand_in, PLAN_B));

    assert_eq!(
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list"),
        grants_before,
        "{UNCHANGED} on a fresh stand-in"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        capsules_before,
        "{UNCHANGED} on a fresh stand-in"
    );
    assert_eq!(
        previews[0].plan, PLAN_A,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[0].sha256,
        sha256(PLAN_A),
        "the hash is sha256 of those bytes"
    );
    assert_eq!(
        previews[1].plan, PLAN_B,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[1].sha256,
        sha256(PLAN_B),
        "the hash is sha256 of those bytes"
    );

    stand_in.seed_grant(
        "req-preview",
        "component-1",
        "localhost://Public/plan-approval/a.txt",
        "read",
        "once",
        1,
        Life::Live,
        false,
    );

    let grants_seeded = stand_in
        .get_capability_list(Caller::Shell, Some("all_sessions_live"))
        .expect("seeded shell live list");
    assert_ne!(grants_seeded, grants_before, "the seeded grant is live");
    let capsules_seeded = stand_in
        .get_capsules(Caller::Shell)
        .expect("seeded shell capsules");

    previews.clear();
    previews.push(preview(&mut stand_in, PLAN_A));
    previews.push(preview(&mut stand_in, PLAN_B));

    assert_eq!(
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list"),
        grants_seeded,
        "{UNCHANGED} after the seeded grant"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        capsules_seeded,
        "{UNCHANGED} after the seeded grant"
    );
    assert_eq!(
        capsules_seeded, capsules_before,
        "the seeded grant leaves the capsule list alone"
    );
    assert_eq!(
        previews[0].plan, PLAN_A,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[0].sha256,
        sha256(PLAN_A),
        "the hash is sha256 of those bytes"
    );
    assert_eq!(
        previews[1].plan, PLAN_B,
        "the preview returned the plan bytes"
    );
    assert_eq!(
        previews[1].sha256,
        sha256(PLAN_B),
        "the hash is sha256 of those bytes"
    );
}

#[cfg(test)]
#[test]
fn plan_sha256_hashes_the_exact_bytes() {
    use agent_conformance::identity::sha256;
    use fixtures::PLAN_A;

    // Real sha2, not a stand-in: the known digest of the empty input.
    assert_eq!(
        plan_sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "the hash is SHA-256 of the given bytes"
    );
    let digest = plan_sha256(PLAN_A);
    assert_eq!(
        digest.len(),
        64,
        "a plan hash is 64 lowercase hex characters: {digest}"
    );
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "a plan hash is lowercase hex: {digest}"
    );
    assert_eq!(
        digest,
        sha256(PLAN_A),
        "the hash is SHA-256 of the plan bytes"
    );

    // One changed byte at the end is another plan.
    let mut last_byte = PLAN_A.to_vec();
    let length = last_byte.len();
    last_byte[length - 1] = b'X';
    assert_eq!(
        plan_sha256(&last_byte),
        sha256(&last_byte),
        "the one changed byte is part of the hashed bytes"
    );
    assert_ne!(
        plan_sha256(&last_byte),
        digest,
        "a plan with one changed byte has another hash"
    );

    // Reordered keys and other whitespace are other bytes, so other hashes:
    // the function does not canonicalise.
    let reordered: &[u8] =
        br#"{"steps":[{"action":"read","resource":"localhost://Public/plan-approval/a.txt"}]}"#;
    let respaced: &[u8] =
        br#"{"steps": [{"resource": "localhost://Public/plan-approval/a.txt", "action": "read"}]}"#;
    assert_eq!(
        plan_sha256(reordered),
        sha256(reordered),
        "reordered keys are hashed as they are"
    );
    assert_ne!(
        plan_sha256(reordered),
        digest,
        "reordered keys are other bytes, so another hash"
    );
    assert_ne!(
        plan_sha256(respaced),
        digest,
        "other whitespace is other bytes, so another hash"
    );
}

/// The one approval helper set, driven through the stand-in's own routes.
#[cfg(test)]
#[path = "../../agent-conformance/tests/common/signed_bundle.rs"]
mod signed_bundle;

#[cfg(test)]
mod journeys {
    use super::preview;
    use super::signed_bundle::SignedBundle;
    use agent_conformance::standin_runtime::{Caller, StandIn, Start};
    use serde_json::json;

    /// One session reaches `Running` through the stand-in's own routes:
    /// `admit_resident` for the signed fixture, `post_capsules` for its CID and
    /// `finish_start`. This mints no grant.
    ///
    /// The stand-in keeps one admitted row per lab CID, so a session after the
    /// first admits the same fixture files with one changed byte through
    /// `SignedBundle::distinct`: another lab CID, another row, the same asks.
    /// A fresh stand-in admits the plain fixture, so the first session is
    /// unchanged. The capsule list is the stand-in's own read of how many
    /// sessions it holds; this journey adds no second launch path.
    pub fn running_agent(stand_in: &mut StandIn) -> String {
        let sessions = stand_in
            .get_capsules(Caller::Shell)
            .expect("the shell reads the capsule list")["capsules"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        let bundle = if sessions == 0 {
            SignedBundle::new()
        } else {
            SignedBundle::distinct(&format!("agent-host-{sessions}"))
        };
        stand_in
            .admit_resident(
                bundle.path(),
                &bundle.signature(),
                bundle.accepted(),
                Start::Ok,
            )
            .expect("the stand-in admits the signed fixture");
        let launched = stand_in
            .post_capsules(Caller::Shell, &bundle.launch_body())
            .expect("the shell launches the admitted CID");
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        stand_in.finish_start(&id).expect("the stand-in starts it");
        id
    }

    /// The agent asks for one plan through `post_capability_request`. The
    /// request id is the stand-in's own, not a fixture name.
    pub fn request(stand_in: &mut StandIn, session: &str, plan: &[u8]) -> String {
        let hash = preview(stand_in, plan).sha256;
        stand_in
            .post_capability_request(
                Caller::Client {
                    session_id: session,
                },
                &json!({
                    "resource": "localhost://Public/plan-approval/a.txt",
                    "action": "read",
                    "plan": hash,
                }),
            )
            .expect("the agent's request route stores one pending request")["request_id"]
            .as_str()
            .expect("the route names the request")
            .to_owned()
    }
}

#[cfg(test)]
#[test]
fn a_grant_bound_to_one_plan_is_refused_for_another_plan() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in);

    let request_a = request(&mut stand_in, &session, PLAN_A);
    let request_b = request(&mut stand_in, &session, PLAN_B);
    assert_ne!(
        request_a, request_b,
        "two plans are two requests, so the two grants differ"
    );

    // The owner approves plan A with grant G1 and plan B with grant G2,
    // naming the hash the shell's request view shows in `plan`.
    let owner_sees_a = plan_sha256(PLAN_A);
    let owner_sees_b = plan_sha256(PLAN_B);
    assert_eq!(
        approve(&mut stand_in, &request_a, &owner_sees_a),
        Ok(json!({ "success": true })),
        "the owner approves plan A"
    );
    assert_eq!(
        approve(&mut stand_in, &request_b, &owner_sees_b),
        Ok(json!({ "success": true })),
        "the owner approves plan B"
    );
    let live = stand_in
        .get_capability_list(
            Caller::Client {
                session_id: &session,
            },
            None,
        )
        .expect("the agent's live list");
    assert_eq!(
        live["capabilities"].as_array().map(Vec::len),
        Some(2),
        "both bound grants are live before the wrong use: {live}"
    );

    // Executing plan A with grant G2 is refused and spends nothing.
    assert_eq!(
        execute(&mut stand_in, &session, &request_b, PLAN_A),
        Err((403, "grant is not bound to this plan".to_owned())),
        "grant G2 is bound to plan B, not plan A"
    );
    assert_eq!(
        stand_in.get_capability_list(
            Caller::Client {
                session_id: &session
            },
            None
        ),
        Ok(live.clone()),
        "the refused wrong-grant use leaves both grants live, byte for byte"
    );

    // Executing plan A with grant G1 spends exactly G1.
    assert_eq!(
        execute(&mut stand_in, &session, &request_a, PLAN_A),
        Ok(json!({ "valid": true })),
        "grant G1 authorises plan A's one use"
    );
    let after = stand_in
        .get_capability_list(
            Caller::Client {
                session_id: &session,
            },
            None,
        )
        .expect("the agent's live list");
    assert_eq!(
        after["capabilities"],
        json!([live["capabilities"][1]]),
        "the once grant G1 is spent and grant G2 is still live: {after}"
    );
    assert_eq!(
        execute(&mut stand_in, &session, &request_b, PLAN_B),
        Ok(json!({ "valid": true })),
        "spending G1 left G2's own plan use intact"
    );
}

#[cfg(test)]
#[test]
fn deny_one_shown_step() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::PLAN_A;
    use serde_json::{json, Value};

    fn live(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .as_array()
            .cloned()
            .expect("the shell live list holds a capabilities array")
    }

    fn requests(stand_in: &StandIn, session: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")
    }

    let mut stand_in = StandIn::new();

    assert_eq!(
        deny_shown_plan(&mut stand_in, "req-absent"),
        Err((400, "unknown request: req-absent".to_owned())),
        "a deny of an absent request settles nothing and names the id"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused deny mints no grant"
    );

    assert_eq!(
        stand_in.seed_request(
            "req-a",
            "component-1",
            "localhost://Public/plan-approval/a.txt",
            "read",
            "shown step a",
        ),
        Ok(()),
        "the stand-in stores the first shown step"
    );
    assert_eq!(
        stand_in.seed_request(
            "req-b",
            "component-1",
            "localhost://Public/plan-approval/b.txt",
            "read",
            "shown step b",
        ),
        Ok(()),
        "the stand-in stores the second shown step"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a pending shown step is not a live grant"
    );

    let shown = requests(&stand_in, "component-1");
    let shown = shown["requests"]
        .as_array()
        .expect("the shell request view holds a requests array");
    assert_eq!(shown.len(), 2, "both shown steps are pending: {shown:?}");
    assert_eq!(
        shown[0],
        json!({
            "request_id": "req-a",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "shown step a",
            "status": "pending",
            "decision_reason": "",
            "settled_by": null,
            "plan": null,
        }),
        "the first shown step is pending with no settler and no plan"
    );
    assert_eq!(
        shown[1],
        json!({
            "request_id": "req-b",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/b.txt",
            "action": "read",
            "reason": "shown step b",
            "status": "pending",
            "decision_reason": "",
            "settled_by": null,
            "plan": null,
        }),
        "the second shown step is pending with no settler and no plan"
    );

    assert_eq!(
        deny_shown_plan(&mut stand_in, "req-a"),
        Ok(json!({ "success": true })),
        "the shell denies the first shown step"
    );
    let after_deny = requests(&stand_in, "component-1");
    let after_deny = after_deny["requests"]
        .as_array()
        .expect("the shell request view holds a requests array");
    assert_eq!(
        after_deny[0],
        json!({
            "request_id": "req-a",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "shown step a",
            "status": "denied",
            "decision_reason": "deny the shown plan",
            "settled_by": "shell",
            "plan": null,
        }),
        "the denied step stores the shell reason and settler"
    );
    assert_eq!(
        after_deny[1]["status"], "pending",
        "a shell deny settles one step and the sibling stays pending"
    );
    assert_eq!(
        after_deny[1]["settled_by"],
        Value::Null,
        "a shell deny settles one step and the sibling stays pending"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a denied step is not a live grant"
    );

    assert_eq!(
        execute(&mut stand_in, "component-1", "req-a", PLAN_A),
        Err((400, "unknown grant".to_owned())),
        "running a denied step is refused with unknown grant, without an id"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused use of the denied step mints nothing"
    );

    assert_eq!(
        stand_in.post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": "req-a",
                "duration": "once",
                "rationale": "owner approved",
            }),
        ),
        Err((400, "request is not pending: req-a".to_owned())),
        "a denied step cannot be granted later"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused late grant mints nothing"
    );

    assert_eq!(
        stand_in.post_capability_grant(
            Caller::Shell,
            &json!({
                "request_id": "req-b",
                "duration": "once",
                "rationale": "owner approved",
            }),
        ),
        Ok(json!({ "success": true })),
        "the sibling stays pending, so its own allow-once grant succeeds"
    );
    let sibling = live(&stand_in);
    assert_eq!(
        sibling.len(),
        1,
        "only the sibling grant is live: {sibling:?}"
    );
    assert_eq!(
        sibling[0]["request_id"], "req-b",
        "the live grant belongs to the sibling request"
    );
    assert_eq!(
        sibling[0]["session_id"], "component-1",
        "the live grant belongs to the one session"
    );
    assert_eq!(
        sibling[0]["resource"], "localhost://Public/plan-approval/b.txt",
        "the live grant names the sibling resource"
    );
    assert_eq!(sibling[0]["action"], "read", "the live grant names read");
    assert_eq!(
        sibling[0]["duration"], "once",
        "the sibling grant authorises one use"
    );

    assert_eq!(
        execute(&mut stand_in, "component-1", "req-a", PLAN_A),
        Err((400, "unknown grant".to_owned())),
        "the denied step still has no grant after its sibling is granted"
    );
    assert_eq!(
        live(&stand_in),
        sibling,
        "the refused denied-step use leaves the sibling grant live"
    );

    assert_eq!(
        execute(&mut stand_in, "component-1", "req-b", PLAN_A),
        Ok(json!({ "valid": true })),
        "the sibling grant authorises its own one use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the once sibling grant is spent"
    );
}

#[cfg(test)]
#[test]
fn unanswered_shown_step_expires() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::Value;

    fn live(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .as_array()
            .cloned()
            .expect("the shell live list holds a capabilities array")
    }

    fn shown(stand_in: &StandIn, session: &str) -> Vec<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
    }

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in);
    assert_eq!(
        session, "component-1",
        "the fresh stand-in names the one session component-1"
    );

    let unanswered = request(&mut stand_in, &session, PLAN_A);
    assert_eq!(
        unanswered, "request-1",
        "the agent's first shown step is the stand-in's first request"
    );
    let allowed = request(&mut stand_in, &session, PLAN_B);
    assert_eq!(
        allowed, "request-2",
        "the agent's second shown step is the stand-in's second request"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        shown(&stand_in, &session)[0]["plan"],
        plan_a,
        "the first shown step carries the hash of plan A"
    );
    assert_eq!(
        shown(&stand_in, &session)[1]["plan"],
        plan_b,
        "the second shown step carries the hash of plan B"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown step is not a live grant before the owner decides"
    );

    assert_eq!(
        approve(&mut stand_in, &allowed, &plan_b),
        Ok(json!({ "success": true })),
        "the owner allows the second shown step once"
    );
    let allowed_live = vec![json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    })];
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the allowed step is the one live grant"
    );

    // At 299 seconds the unanswered step is still pending and is still not a
    // live grant; the allowed step's record and its live grant stay.
    age_shown_plan(&mut stand_in, 299);
    let aged = shown(&stand_in, &session);
    assert_eq!(
        aged[0],
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "pending",
            "decision_reason": "",
            "settled_by": null,
            "plan": plan_a,
        }),
        "an unanswered shown step is still pending at 299 seconds"
    );
    assert_eq!(
        aged[1],
        json!({
            "request_id": "request-2",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "granted",
            "decision_reason": "owner approved",
            "settled_by": "shell",
            "plan": plan_b,
        }),
        "the allowed step stays a grant and keeps its plan hash at 299 seconds"
    );
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the allowed step stays a grant and the unanswered step is not live at 299 seconds"
    );

    // At 300 seconds the unanswered step expires through the stand-in's own
    // clock; the allowed step's record and its live grant stay.
    age_shown_plan(&mut stand_in, 300);
    let expired = shown(&stand_in, &session);
    assert_eq!(
        expired[0],
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "expired",
            "decision_reason": "Request timed out",
            "settled_by": "runtime",
            "plan": plan_a,
        }),
        "an unanswered shown step expires at 300 seconds and keeps its plan hash"
    );
    assert_eq!(
        expired[1],
        json!({
            "request_id": "request-2",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "granted",
            "decision_reason": "owner approved",
            "settled_by": "shell",
            "plan": plan_b,
        }),
        "the allowed step stays a grant and keeps its plan hash at 300 seconds"
    );
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the allowed step stays a grant when the unanswered step expires"
    );

    // An expired shown step is not a live grant and cannot be granted later.
    assert_eq!(
        approve(&mut stand_in, &unanswered, &plan_a),
        Err((400, "request is not pending: request-1".to_owned())),
        "an expired shown step cannot be granted later"
    );
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the refused late grant of the expired step mints nothing and the allowed step stays a grant"
    );

    assert_eq!(
        execute(&mut stand_in, &session, &unanswered, PLAN_A),
        Err((400, "unknown grant".to_owned())),
        "an expired shown step is not a live grant, so running it is refused with unknown grant"
    );
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the refused use of the expired step mints nothing and the allowed step stays a grant"
    );

    // The allowed step still authorises exactly its own one use.
    assert_eq!(
        execute(&mut stand_in, &session, &allowed, PLAN_B),
        Ok(json!({ "valid": true })),
        "the allowed step stays a grant and authorises its own one use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the once allowed step is spent by its one use"
    );
}

#[cfg(test)]
#[test]
fn stop_settles_that_sessions_shown_steps() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn live(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .as_array()
            .cloned()
            .expect("the shell live list holds a capabilities array")
    }

    fn shown(stand_in: &StandIn, session: &str) -> Vec<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
    }

    fn capsule(stand_in: &StandIn, id: &str) -> Value {
        let listed = stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules");
        listed["capsules"]
            .as_array()
            .and_then(|capsules| capsules.iter().find(|entry| entry["id"] == id))
            .cloned()
            .unwrap_or_else(|| panic!("the capsule list names {id}: {listed}"))
    }

    let mut stand_in = StandIn::new();

    // A stop of an absent session refuses with the stand-in's own reason and
    // settles nothing.
    assert_eq!(
        stop_shown_session(&mut stand_in, "component-absent"),
        Err((400, "unknown instance: component-absent".to_owned())),
        "a stop of an absent session refuses with the id it named"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        json!({ "capsules": [] }),
        "the refused stop mints no instance"
    );

    // Two sessions come from the one launch journey.
    let first = running_agent(&mut stand_in);
    let second = running_agent(&mut stand_in);
    assert_eq!(first, "component-1", "the first launch is component-1");
    assert_eq!(second, "component-2", "the second launch is component-2");
    assert_eq!(
        {
            let shown = capsule(&stand_in, &first);
            json!({ "id": shown["id"], "status": shown["status"], "cause": shown["cause"] })
        },
        json!({ "id": "component-1", "status": "running", "cause": "" }),
        "the shown session starts running with no cause"
    );
    assert_eq!(
        {
            let other = capsule(&stand_in, &second);
            json!({ "id": other["id"], "status": other["status"], "cause": other["cause"] })
        },
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "the other session starts running with no cause"
    );

    // The agent's own request route stores each shown step.
    let pending_step = request(&mut stand_in, &first, PLAN_A);
    let allowed_step = request(&mut stand_in, &first, PLAN_B);
    let other_step = request(&mut stand_in, &second, PLAN_A);
    assert_eq!(
        pending_step, "request-1",
        "the first shown step is the stand-in's first request"
    );
    assert_eq!(
        allowed_step, "request-2",
        "the second shown step is the stand-in's second request"
    );
    assert_eq!(
        other_step, "request-3",
        "the other session's step is the stand-in's third request"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);

    // The owner allows the second step once, with the hash it saw.
    assert_eq!(
        approve(&mut stand_in, &allowed_step, &plan_b),
        Ok(json!({ "success": true })),
        "the owner allows the second shown step once"
    );
    let allowed_live = live(&stand_in);
    assert_eq!(
        allowed_live.len(),
        1,
        "the allowed step is the one live grant: {allowed_live:?}"
    );
    assert_eq!(
        allowed_live[0]["request_id"], "request-2",
        "the live grant belongs to the allowed step"
    );
    assert_eq!(
        allowed_live[0]["session_id"], "component-1",
        "the allowed step's grant belongs to the shown session"
    );

    // The stop reports its settlement as JSON null.
    assert_eq!(
        stop_shown_session(&mut stand_in, &first),
        Ok(Value::Null),
        "a stop reports its settlement"
    );

    let settled = shown(&stand_in, &first);
    assert_eq!(
        settled[0],
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "denied",
            "decision_reason": "stopped: stop the shown session",
            "settled_by": "runtime",
            "plan": plan_a,
        }),
        "a stop settles that session's shown steps: the pending step is denied by the runtime with the stop cause, and it keeps its plan hash"
    );
    assert_eq!(
        settled[1],
        json!({
            "request_id": "request-2",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "granted",
            "decision_reason": "owner approved",
            "settled_by": "shell",
            "plan": plan_b,
        }),
        "a stop leaves the granted record granted, with its own settler and plan hash"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a stop revokes that session's allow-once grant"
    );

    // The revoked allow-once grant is refused through the existing use path.
    assert_eq!(
        execute(&mut stand_in, &first, &allowed_step, PLAN_B),
        Err((400, "grant is not live: Revoked".to_owned())),
        "the revoked allow-once grant refuses its own plan's use"
    );

    let untouched = shown(&stand_in, &second);
    assert_eq!(
        untouched[0],
        json!({
            "request_id": "request-3",
            "session_id": "component-2",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "pending",
            "decision_reason": "",
            "settled_by": null,
            "plan": plan_a,
        }),
        "a stop settles that session's shown steps and leaves the other session pending"
    );

    assert_eq!(
        {
            let stopped = capsule(&stand_in, &first);
            json!({ "status": stopped["status"], "cause": stopped["cause"] })
        },
        json!({ "status": "stopped", "cause": "stopped: stop the shown session" }),
        "the stopped session stores stopped and the stop cause"
    );
    assert_eq!(
        {
            let other = capsule(&stand_in, &second);
            json!({ "status": other["status"], "cause": other["cause"] })
        },
        json!({ "status": "running", "cause": "" }),
        "a stop settles that session's shown steps and leaves the other session running"
    );

    // The other session's pending step is the next live grant.
    assert_eq!(
        approve(&mut stand_in, &other_step, &plan_a),
        Ok(json!({ "success": true })),
        "the other session's pending step can still be allowed once"
    );
    let other_live = live(&stand_in);
    assert_eq!(
        other_live.len(),
        1,
        "the other session's allowed step is the one live grant: {other_live:?}"
    );
    assert_eq!(
        other_live[0]["request_id"], "request-3",
        "the live grant belongs to the other session's step"
    );
    assert_eq!(
        other_live[0]["session_id"], "component-2",
        "the live grant belongs to the other session"
    );
    assert_eq!(
        other_live[0]["resource"], "localhost://Public/plan-approval/a.txt",
        "the live grant names the requested resource"
    );
    assert_eq!(
        other_live[0]["action"], "read",
        "the live grant names the requested action"
    );
    assert_eq!(
        other_live[0]["duration"], "once",
        "the live grant authorises one use"
    );

    assert_eq!(
        execute(&mut stand_in, &second, &other_step, PLAN_A),
        Ok(json!({ "valid": true })),
        "the other session's allow-once grant authorises its own use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the other session's once grant is spent by its one use"
    );

    assert_eq!(
        stop_shown_session(&mut stand_in, &first),
        Err((400, "instance is not live: stopped".to_owned())),
        "a stop of an already stopped session refuses with its status"
    );
}
