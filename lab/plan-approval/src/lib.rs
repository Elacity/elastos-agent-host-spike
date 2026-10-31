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

/// The agent runs one plan through `POST /api/capability/validate`.
///
/// The agent asks for the hash of the bytes it holds now, so a plan that
/// changed after approval is refused by the stand-in with status 403 and
/// `grant is not bound to this plan`, and a `once` grant stays `Live`.
/// It asks `amount: 1` so these tests exercise plan binding, never the budget.
pub fn execute(
    stand_in: &mut StandIn,
    session_id: &str,
    request_id: &str,
    plan: &[u8],
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_validate(
        Caller::Client { session_id },
        &json!({
            "request_id": request_id,
            "plan_sha256": plan_sha256(plan),
            "amount": 1,
        }),
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
    pub fn running_agent(stand_in: &mut StandIn) -> String {
        let bundle = SignedBundle::new();
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
