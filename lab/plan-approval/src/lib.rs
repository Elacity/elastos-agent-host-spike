#![forbid(unsafe_code)]

//! Plan preview: the bytes and their hash, and nothing else.
//!
//! A proposal carries no authority, so a preview reads no grant and no
//! capsule list and writes neither. Runtime authorisation is a separate step.

use agent_conformance::standin_runtime::StandIn;

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
        sha256: agent_conformance::identity::sha256(plan),
    }
}

#[cfg(test)]
mod fixtures {
    use serde_json::Value;
    use std::collections::BTreeSet;

    pub const PLAN_A: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"read"}]}"#;
    pub const PLAN_B: &[u8] =
        br#"{"steps":[{"resource":"localhost://Public/plan-approval/b.txt","action":"read"}]}"#;
    pub const RESIDENT_PATH: &str = "/capsules/plan-preview";
    pub const RESIDENT_NAME: &str = "plan-preview";
    pub const GRANT_RESOURCE: &str = "localhost://Public/plan-approval/a.txt";
    pub const UNCHANGED: &str = "the preview returned the plan bytes, the hash is sha256 of those bytes, and the live grants and the capsule list are unchanged";

    /// The request ids of one capability list body.
    pub fn grant_ids(body: &Value) -> BTreeSet<String> {
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

    /// The ids of one capsule list body.
    pub fn capsule_ids(body: &Value) -> BTreeSet<String> {
        body["capsules"]
            .as_array()
            .expect("the stand-in returns a capsule list")
            .iter()
            .map(|entry| {
                entry["id"]
                    .as_str()
                    .expect("the stand-in capsule entry names id")
                    .to_owned()
            })
            .collect()
    }
}

#[cfg(test)]
#[test]
fn preview_makes_no_effect() {
    use agent_conformance::identity::sha256;
    use agent_conformance::standin_runtime::{Caller, Start};
    use fixtures::{
        capsule_ids, grant_ids, GRANT_RESOURCE, PLAN_A, PLAN_B, RESIDENT_NAME, RESIDENT_PATH,
        UNCHANGED,
    };
    use serde_json::json;
    use std::collections::BTreeSet;

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

    stand_in
        .admit_resident(RESIDENT_PATH, RESIDENT_NAME, Start::Ok)
        .expect("the stand-in admits the plan-approval resident");
    let launched = stand_in
        .post_capsules(Caller::Shell, &json!({ "path": RESIDENT_PATH }))
        .expect("the stand-in launches the resident");
    let session_id = launched["id"]
        .as_str()
        .expect("the stand-in names the launched instance")
        .to_owned();
    stand_in
        .finish_start(&session_id)
        .expect("the stand-in starts the resident");
    let pending = stand_in
        .post_capability_request(
            Caller::Client {
                session_id: &session_id,
            },
            &json!({ "resource": GRANT_RESOURCE, "action": "read" }),
        )
        .expect("the stand-in stores the resident's request");
    let request_id = pending["request_id"]
        .as_str()
        .expect("the stand-in names the request")
        .to_owned();
    let granted = stand_in
        .post_capability_grant(
            Caller::Shell,
            &json!({ "request_id": request_id, "duration": "once" }),
        )
        .expect("the stand-in's shell grants the resident's request");
    assert_eq!(
        granted,
        json!({ "success": true }),
        "the stand-in did the work: the shell granted the pending request"
    );
    assert_eq!(
        grant_ids(
            &stand_in
                .get_capability_list(Caller::Shell, Some("all_sessions_live"))
                .expect("seeded shell live list")
        ),
        BTreeSet::from([request_id.clone()]),
        "the seeded grant is live"
    );

    let grants_seeded: serde_json::Value = stand_in
        .get_capability_list(Caller::Shell, Some("all_sessions_live"))
        .expect("seeded shell live list");
    assert_ne!(grants_seeded, grants_before, "the seeded grant is live");

    previews.clear();
    previews.push(preview(&mut stand_in, PLAN_A));
    previews.push(preview(&mut stand_in, PLAN_B));

    let capsules_seeded = stand_in
        .get_capsules(Caller::Shell)
        .expect("seeded shell capsules");

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
        capsule_ids(&capsules_seeded),
        BTreeSet::from([session_id.clone()]),
        "the stand-in did the work: the granted resident is listed as a capsule"
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
