#![forbid(unsafe_code)]

//! Plan preview and approval: the bytes and their hash, and the stand-in's
//! shell grant or deny for one exact step.
//!
//! A proposal carries no authority, so a preview reads no grant and no
//! capsule list and writes neither. Runtime authorisation is a separate step:
//! the shell grant binds the shown hash, and a later byte change is refused.

use agent_conformance::standin_runtime::{Caller, StandIn};

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

/// Submit one step of the shown plan as a pending request.
///
/// The request `reason` is the preview hash. A hash that does not name these
/// bytes, or a step the bytes do not contain, is refused before any request
/// is stored.
pub fn submit_shown_plan(
    stand_in: &mut StandIn,
    preview: &Preview,
    session_id: &str,
    request_id: &str,
    resource: &str,
    action: &str,
) -> Result<(), (u16, String)> {
    if agent_conformance::identity::sha256(&preview.plan) != preview.sha256 {
        return Err((400, "plan hash does not name these bytes".to_owned()));
    }
    let Ok(text) = std::str::from_utf8(&preview.plan) else {
        return Err((400, "step is not in the shown plan".to_owned()));
    };
    if !(text.contains(resource) && text.contains(action)) {
        return Err((400, "step is not in the shown plan".to_owned()));
    }
    stand_in.seed_request(request_id, session_id, resource, action, &preview.sha256)
}

/// Grant the pending request through the shell grant for one use.
pub fn grant_shown_plan(
    stand_in: &mut StandIn,
    request_id: &str,
) -> Result<serde_json::Value, (u16, String)> {
    stand_in.post_capability_grant(
        Caller::Shell,
        &serde_json::json!({
            "request_id": request_id,
            "duration": "once",
            "rationale": "allow once the shown plan",
        }),
    )
}

/// Deny one pending shown request through the shell, with one fixed reason.
///
/// A deny is the other settlement of the step the request records. It settles
/// that one request and writes no grant, so its sibling step stays pending for
/// its own allow-once grant.
pub fn deny_shown_plan(
    stand_in: &mut StandIn,
    request_id: &str,
) -> Result<serde_json::Value, (u16, String)> {
    stand_in.post_capability_deny(
        Caller::Shell,
        &serde_json::json!({
            "request_id": request_id,
            "reason": "deny the shown plan",
        }),
    )
}

/// Perform the shown plan through the request the shell grant settled.
///
/// The `approved` flag grants nothing. The recomputed hash must equal the
/// request's stored `reason`, so a later byte change is refused.
pub fn perform_shown_plan(
    stand_in: &mut StandIn,
    preview: &Preview,
    session_id: &str,
    request_id: &str,
    approved: bool,
) -> Result<(), (u16, String)> {
    let _ = approved;
    let shown = agent_conformance::identity::sha256(&preview.plan);
    if shown != preview.sha256 {
        return Err((400, "plan hash does not name these bytes".to_owned()));
    }
    let requests = stand_in.get_capability_requests(Caller::Shell, Some(session_id))?;
    let reason = requests["requests"]
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["request_id"] == request_id)
        })
        .and_then(|entry| entry["reason"].as_str())
        .ok_or_else(|| (400, format!("unknown request: {request_id}")))?;
    if reason != shown.as_str() {
        return Err((400, "plan bytes differ from the approved hash".to_owned()));
    }
    stand_in.authorise(Caller::Client { session_id }, request_id)
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
fn approval_binds_to_the_previewed_plan_hash() {
    use agent_conformance::identity::sha256;
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use serde_json::{json, Value};

    const SESSION: &str = "component-1";
    const REQUEST: &str = "req-plan";
    const RESOURCE: &str = "localhost://Public/plan-approval/a.txt";
    const ACTION: &str = "read";
    const BOUND: &str = "the shell grant bound the shown hash and the flag granted nothing";

    fn live(stand_in: &StandIn) -> Value {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .clone()
    }

    fn requests(stand_in: &StandIn, session_id: &str) -> Vec<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session_id))
            .expect("shell requests")["requests"]
            .as_array()
            .expect("requests array")
            .clone()
    }

    fn listed(stand_in: &StandIn, session_id: &str) -> Option<Value> {
        requests(stand_in, session_id)
            .into_iter()
            .find(|entry| entry["request_id"] == json!(REQUEST))
    }

    let mut stand_in = StandIn::new();
    let shown = preview(&mut stand_in, PLAN_A);
    assert_eq!(
        submit_shown_plan(&mut stand_in, &shown, SESSION, REQUEST, RESOURCE, ACTION),
        Ok(()),
        "a step the shown bytes contain becomes one pending request"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a pending request is not a live grant"
    );

    let pending = listed(&stand_in, SESSION).expect("the shown plan request is listed");
    assert_eq!(
        pending["status"],
        json!("pending"),
        "the request is pending"
    );
    assert_eq!(
        pending["reason"],
        json!(sha256(PLAN_A)),
        "the pending request carries the shown hash as its reason"
    );
    assert_eq!(pending["settled_by"], Value::Null, "no settler yet");

    let err = perform_shown_plan(&mut stand_in, &shown, SESSION, REQUEST, true).unwrap_err();
    assert_eq!(err.0, 400, "a pending request authorises nothing");
    assert!(
        err.1.contains("unknown grant: req-plan"),
        "{BOUND}: {err:?}"
    );
    assert_eq!(live(&stand_in), json!([]), "{BOUND}");

    let before = requests(&stand_in, SESSION).len();
    assert_eq!(
        submit_shown_plan(
            &mut stand_in,
            &shown,
            SESSION,
            "req-missing",
            "localhost://Public/plan-approval/missing.txt",
            ACTION
        ),
        Err((400, "step is not in the shown plan".to_owned())),
        "a step the shown bytes do not contain is refused"
    );
    assert_eq!(
        requests(&stand_in, SESSION).len(),
        before,
        "a refused step adds no request"
    );

    let forged = Preview {
        plan: PLAN_A.to_vec(),
        sha256: "0".repeat(64),
    };
    assert_eq!(
        submit_shown_plan(
            &mut stand_in,
            &forged,
            SESSION,
            "req-forged",
            RESOURCE,
            ACTION
        ),
        Err((400, "plan hash does not name these bytes".to_owned())),
        "a hash that does not name the bytes is refused"
    );
    assert_eq!(
        requests(&stand_in, SESSION).len(),
        before,
        "a forged hash adds no request"
    );

    let err = perform_shown_plan(&mut stand_in, &forged, SESSION, REQUEST, true).unwrap_err();
    assert_eq!(
        err,
        (400, "plan hash does not name these bytes".to_owned()),
        "perform refuses a hash that does not name the bytes"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a forged perform leaves the live grants unchanged"
    );

    let mut stray = PLAN_A.to_vec();
    stray.push(0xff);
    let not_utf8 = preview(&mut stand_in, &stray);
    assert_eq!(
        submit_shown_plan(
            &mut stand_in,
            &not_utf8,
            SESSION,
            "req-utf8",
            RESOURCE,
            ACTION
        ),
        Err((400, "step is not in the shown plan".to_owned())),
        "bytes that are not UTF-8 carry no step"
    );
    assert_eq!(
        requests(&stand_in, SESSION).len(),
        before,
        "a non-UTF-8 plan adds no request"
    );

    assert_eq!(
        submit_shown_plan(
            &mut stand_in,
            &shown,
            SESSION,
            "req-action",
            RESOURCE,
            "delete"
        ),
        Err((400, "step is not in the shown plan".to_owned())),
        "an action the shown bytes do not contain is refused"
    );
    assert_eq!(
        requests(&stand_in, SESSION).len(),
        before,
        "an absent action adds no request"
    );

    let err = perform_shown_plan(&mut stand_in, &shown, SESSION, "req-unknown", true).unwrap_err();
    assert_eq!(
        err,
        (400, "unknown request: req-unknown".to_owned()),
        "perform refuses a request no listing holds"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "an unknown request leaves the live grants unchanged"
    );

    assert_eq!(
        grant_shown_plan(&mut stand_in, REQUEST),
        Ok(json!({ "success": true })),
        "the shell grant settles the pending request"
    );
    let granted = listed(&stand_in, SESSION).expect("the granted request is listed");
    assert_eq!(
        granted["status"],
        json!("granted"),
        "the request is granted"
    );
    assert_eq!(
        granted["settled_by"],
        json!("shell"),
        "the shell settled it"
    );
    assert_eq!(
        granted["decision_reason"],
        json!("allow once the shown plan"),
        "the rationale is the allow-once text"
    );
    assert_eq!(
        granted["reason"],
        json!(sha256(PLAN_A)),
        "the shell grant bound the shown hash"
    );

    let live_grant = live(&stand_in);
    assert_eq!(
        live_grant.as_array().map(Vec::len),
        Some(1),
        "the shell grant is one live grant"
    );
    assert_eq!(live_grant[0]["request_id"], json!(REQUEST), "{BOUND}");
    assert_eq!(live_grant[0]["session_id"], json!(SESSION), "{BOUND}");
    assert_eq!(live_grant[0]["resource"], json!(RESOURCE), "{BOUND}");
    assert_eq!(live_grant[0]["action"], json!(ACTION), "{BOUND}");
    assert_eq!(live_grant[0]["duration"], json!("once"), "{BOUND}");

    let other = preview(&mut stand_in, PLAN_B);
    assert_eq!(
        perform_shown_plan(&mut stand_in, &other, SESSION, REQUEST, false),
        Err((400, "plan bytes differ from the approved hash".to_owned())),
        "{BOUND}"
    );
    assert_eq!(
        live(&stand_in),
        live_grant,
        "a refused plan leaves the live grant in place"
    );

    assert_eq!(
        perform_shown_plan(&mut stand_in, &shown, SESSION, REQUEST, false),
        Ok(()),
        "{BOUND}: allow once authorizes one exact operation"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "{BOUND}: the once grant is spent"
    );

    let err = perform_shown_plan(&mut stand_in, &shown, SESSION, REQUEST, false).unwrap_err();
    assert_eq!(
        err,
        (400, "grant is not live: Exhausted".to_owned()),
        "{BOUND}: a spent once grant authorises no second operation"
    );
}

#[cfg(test)]
#[test]
fn deny_one_shown_step() {
    use agent_conformance::identity::sha256;
    use agent_conformance::standin_runtime::Caller;
    use serde_json::{json, Value};

    const PLAN_TWO: &[u8] = br#"{"steps":[{"resource":"localhost://Public/plan-approval/a.txt","action":"read"},{"resource":"localhost://Public/plan-approval/b.txt","action":"read"}]}"#;
    const SESSION: &str = "component-1";
    const RESOURCE_A: &str = "localhost://Public/plan-approval/a.txt";
    const RESOURCE_B: &str = "localhost://Public/plan-approval/b.txt";
    const ACTION: &str = "read";
    const SETTLES_ONE: &str = "a shell deny settles one step and the sibling stays pending";

    fn live(stand_in: &StandIn) -> Value {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .clone()
    }

    fn listed(stand_in: &StandIn, session_id: &str, request_id: &str) -> Option<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session_id))
            .expect("shell requests")["requests"]
            .as_array()
            .expect("requests array")
            .iter()
            .find(|entry| entry["request_id"] == json!(request_id))
            .cloned()
    }

    let mut stand_in = StandIn::new();
    assert_eq!(
        deny_shown_plan(&mut stand_in, "req-absent"),
        Err((400, "unknown request: req-absent".to_owned())),
        "a request no listing holds is refused"
    );
    assert_eq!(live(&stand_in), json!([]), "a refused deny writes no grant");

    let shown = preview(&mut stand_in, PLAN_TWO);
    assert_eq!(
        submit_shown_plan(&mut stand_in, &shown, SESSION, "req-a", RESOURCE_A, ACTION),
        Ok(()),
        "the first shown step becomes one pending request"
    );
    assert_eq!(
        submit_shown_plan(&mut stand_in, &shown, SESSION, "req-b", RESOURCE_B, ACTION),
        Ok(()),
        "the sibling shown step becomes its own pending request"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a pending request is not a live grant"
    );

    for request_id in ["req-a", "req-b"] {
        let pending = listed(&stand_in, SESSION, request_id).expect("the shown step is listed");
        assert_eq!(pending["status"], json!("pending"), "{SETTLES_ONE}");
        assert_eq!(
            pending["reason"],
            json!(sha256(PLAN_TWO)),
            "each request carries the shown hash as its reason"
        );
        assert_eq!(pending["settled_by"], Value::Null, "no settler yet");
    }

    assert_eq!(
        deny_shown_plan(&mut stand_in, "req-a"),
        Ok(json!({ "success": true })),
        "the shell deny settles the one request"
    );
    let denied = listed(&stand_in, SESSION, "req-a").expect("the denied request is listed");
    assert_eq!(denied["status"], json!("denied"), "{SETTLES_ONE}");
    assert_eq!(denied["settled_by"], json!("shell"), "{SETTLES_ONE}");
    assert_eq!(
        denied["decision_reason"],
        json!("deny the shown plan"),
        "{SETTLES_ONE}"
    );
    assert_eq!(
        denied["reason"],
        json!(sha256(PLAN_TWO)),
        "the deny keeps the shown hash"
    );

    let sibling = listed(&stand_in, SESSION, "req-b").expect("the sibling request is listed");
    assert_eq!(sibling["status"], json!("pending"), "{SETTLES_ONE}");
    assert_eq!(sibling["settled_by"], Value::Null, "{SETTLES_ONE}");
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a denied step is not a live grant"
    );

    let err = perform_shown_plan(&mut stand_in, &shown, SESSION, "req-a", true).unwrap_err();
    assert_eq!(err.0, 400, "{SETTLES_ONE}");
    assert!(
        err.1.contains("unknown grant: req-a"),
        "{SETTLES_ONE}: {err:?}"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a denied step authorises nothing"
    );

    assert_eq!(
        grant_shown_plan(&mut stand_in, "req-a"),
        Err((400, "request is not pending: req-a".to_owned())),
        "a denied step cannot be granted later"
    );
    assert_eq!(
        live(&stand_in),
        json!([]),
        "a refused grant writes no grant"
    );

    assert_eq!(
        grant_shown_plan(&mut stand_in, "req-b"),
        Ok(json!({ "success": true })),
        "the sibling step takes its own allow-once grant"
    );
    let grants = live(&stand_in);
    assert_eq!(grants.as_array().map(Vec::len), Some(1), "{SETTLES_ONE}");
    assert_eq!(grants[0]["request_id"], json!("req-b"), "{SETTLES_ONE}");
    assert_eq!(grants[0]["session_id"], json!(SESSION), "{SETTLES_ONE}");
    assert_eq!(grants[0]["resource"], json!(RESOURCE_B), "{SETTLES_ONE}");
    assert_eq!(grants[0]["action"], json!(ACTION), "{SETTLES_ONE}");
    assert_eq!(grants[0]["duration"], json!("once"), "{SETTLES_ONE}");

    let err = perform_shown_plan(&mut stand_in, &shown, SESSION, "req-a", true).unwrap_err();
    assert!(
        err.1.contains("unknown grant: req-a"),
        "{SETTLES_ONE}: {err:?}"
    );
    assert_eq!(live(&stand_in), grants, "the sibling grant stays live");

    assert_eq!(
        perform_shown_plan(&mut stand_in, &shown, SESSION, "req-b", false),
        Ok(()),
        "the sibling allow-once grant authorizes its one exact operation"
    );
    assert_eq!(live(&stand_in), json!([]), "the once grant is spent");
}
