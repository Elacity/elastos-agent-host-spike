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
