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
/// `caller` is the authenticated caller, a method argument. This helper passes
/// it to the grant route unchanged and does not judge it, so the route's own
/// shell-only check runs before the body is read: a client caller, including
/// the session that posted the shown plan, is refused and mints nothing.
///
/// `duration` is the word the owner chose, `once` or `session`; this helper
/// sends it as the route's `duration` key and does not judge it, so another
/// word reaches the stand-in's own refusal. A `session` grant lasts until that
/// session stops.
///
/// `plan_sha256` is the plan hash the owner saw with the request, the value the
/// shell's request view shows in `plan`. The grant route mints the binding from
/// that hash only when it equals the hash the agent requested; a missing or
/// different hash is refused and the request stays pending.
///
/// `rationale` is the text the owner states with that decision, a method
/// argument. This helper passes it unchanged as the route's `rationale` key and
/// does not judge it, so the route stores it on the shown request as
/// `decision_reason`; the live grant entry keeps no copy. That text is the
/// decision reason, not the grant.
pub fn approve(
    stand_in: &mut StandIn,
    caller: Caller<'_>,
    request_id: &str,
    duration: &str,
    plan_sha256: &str,
    rationale: &str,
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_grant(
        caller,
        &json!({
            "request_id": request_id,
            "duration": duration,
            "rationale": rationale,
            "plan_sha256": plan_sha256,
        }),
    )
}

/// The owner denies one shown step through `POST /api/capability/deny`.
///
/// `caller` is the authenticated caller, a method argument. This helper passes
/// it to the deny route unchanged and does not judge it, so the route's own
/// shell-only check runs before the deny body is read: a client caller,
/// including the session that posted the shown plan and the other running
/// session, is refused and settles nothing, even for an id that was never
/// stored.
///
/// The call is the shell's refusal of the pending request the owner saw. It
/// stores `denied` with `shell` as settler and mints no grant, so a denied
/// step is not live and cannot be granted later.
///
/// `reason` is the text the owner states with that refusal, a method argument.
/// This helper passes it unchanged as the route's `reason` key and does not
/// judge it, so the route stores it on the shown request as `decision_reason`;
/// that text is the settlement record and is not the grant. A reason that
/// reads like an allow word still denies and mints nothing, and the empty
/// string stays the empty string.
pub fn deny_shown_plan(
    stand_in: &mut StandIn,
    caller: Caller<'_>,
    request_id: &str,
    reason: &str,
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_deny(
        caller,
        &json!({
            "request_id": request_id,
            "reason": reason,
        }),
    )
}

/// The agent runs one plan through `POST /api/capability/validate`.
///
/// `caller` is the authenticated caller, a method argument. This helper passes
/// it to the use route unchanged and does not judge it, so the route's own
/// instance-session check runs before the body is read: a shell caller is
/// refused and spends nothing. Another session's use of a shown grant is
/// refused and spends nothing.
///
/// The agent asks for the hash of the bytes it holds now, so a plan that
/// changed after approval is refused by the stand-in with status 403 and
/// `grant is not bound to this plan`, and a `once` grant stays `Live`.
pub fn execute(
    stand_in: &mut StandIn,
    caller: Caller<'_>,
    request_id: &str,
    plan: &[u8],
) -> Result<Value, (u16, String)> {
    stand_in.post_capability_validate(
        caller,
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

/// One session stop through `DELETE /api/capsules/:id`.
///
/// `caller` is the authenticated caller, a method argument. This helper passes
/// it to the stop route unchanged and does not judge it, so the route's own
/// shell-only check runs before the stop body is read: a client caller,
/// including the session that posted the shown plan and the other running
/// session, is refused and stops nothing, even for an id that was never
/// stored or an empty id.
///
/// `reason` is the text the owner states with this stop, a method argument.
/// This helper passes it unchanged as the route's only body key `reason` and
/// returns that route's result. The call is the cancel settlement the design
/// names: "an explicit interrupt or cancel operation that reports its
/// settlement". The stand-in stores that text as the capsule cause and as the
/// decision reason of that session's pending requests, with `runtime` as
/// settler, and revokes that session's `Live` grants. The text is the
/// settlement record and is not a grant: a reason that reads like an allow
/// word still stops, and the empty string reaches the route's own reason
/// refusal. A granted record stays `granted`, another session stays as it was,
/// and Ok is JSON null. The helper takes no plan and no approved flag.
pub fn stop_shown_session(
    stand_in: &mut StandIn,
    caller: Caller<'_>,
    session_id: &str,
    reason: &str,
) -> Result<Value, (u16, String)> {
    stand_in.delete_capsule(caller, session_id, &json!({ "reason": reason }))
}

/// One worker reap through the stand-in's own reap seam.
///
/// `session_id` is the instance id, a method argument. This helper passes it to
/// that seam unchanged and returns its result, so the stand-in's own lookup and
/// its own live check decide the answer. An unknown id is status 400 with the
/// reason that names it and stores nothing. An instance that is not `starting`
/// or `running` is status 400 with the not-live reason, and its stored cause
/// stays. A live instance becomes `failed` with the stand-in's fixed cause; that
/// session's pending requests are denied with that same cause and `runtime` as
/// settler, and its live grants are revoked. A granted record stays `granted`
/// and another session stays as it was. Ok is `()`.
///
/// The helper takes no caller and no reason, so the cause is not text this
/// crate states. It is not the stop route: this crate stores no copy of the
/// stand-in's end path, its settle step or its revoke step, and it does not
/// watch the worker.
pub fn shown_worker_exited(stand_in: &mut StandIn, session_id: &str) -> Result<(), (u16, String)> {
    stand_in.worker_exited(session_id)
}

/// One status read of a shown request through
/// `GET /api/capability/request/:id`.
///
/// `caller` is the authenticated caller, a method argument. This helper passes
/// it to the status route unchanged and does not judge it, so the route's own
/// lookup and owner check decide the answer. The lookup runs first: a missing
/// id is the not-found answer that names that id, for the owning session, for
/// another session, for an empty session id and for the shell. An existing id
/// that another session, an empty session id or the shell asks for is the
/// other-session refusal.
///
/// The owning session's Ok is the stored status word, `pending`, `granted`,
/// `denied` or `expired`, and for a denied or expired record the decision
/// reason. That body carries no plan, no resource, no request id and no token.
/// A read stores nothing and spends nothing: the shell request view and the
/// live grant list stay as they were. The status is not the grant; only the
/// owner's `approve` mints one.
pub fn read_shown_request(
    stand_in: &StandIn,
    caller: Caller<'_>,
    request_id: &str,
) -> Result<Value, (u16, String)> {
    stand_in.get_capability_request(caller, request_id)
}

/// One live-list read through `GET /api/capability/list`.
///
/// `caller` is the authenticated caller and `scope` is the query scope, both
/// method arguments. This helper passes them to the list route unchanged and
/// does not judge either, so the route's own scope check and its own shell
/// check decide the answer. No scope is the plain route; the one live scope
/// lists every live grant, and the route returns the same body for both.
///
/// A scope the route does not know, the empty string included, is the route's
/// status 400 with its scope reason, for the shell and for a client alike,
/// because the scope check runs before the caller check. The live scope then
/// requires the shell: a client is refused with the shell-only reason. A
/// client on the plain route receives only its own live grants; each entry
/// omits the session id and the plan, and the body carries no scope. A pending
/// request is not a live grant, so it stays out of this list. A read stores
/// nothing and spends nothing: the stored requests and the live grants stay as
/// they were, so a `session` grant stays listed until its session stops.
pub fn read_shown_grants(
    stand_in: &StandIn,
    caller: Caller<'_>,
    scope: Option<&str>,
) -> Result<Value, (u16, String)> {
    stand_in.get_capability_list(caller, scope)
}

/// One per-session request-list read through
/// `GET /api/capability/requests?session=`.
///
/// `caller` is the authenticated caller and `session` is the query, both method
/// arguments. This helper passes them to the list route unchanged and does not
/// judge either, so the route's own shell check and its own session check
/// decide the answer. The shell check runs first: a client is refused with the
/// shell-only reason for a named session, for an empty session and for no
/// session. A shell with no session, or with an empty session, is refused with
/// the route's session reason. A shell with any other session, including a
/// session that was never launched, is `{"requests":[]}` when that session has
/// no records.
///
/// The list holds that session's records and no other session's, sorted by
/// `request_id`. Each entry is the stand-in's own record: the request id, the
/// session id, the resource, the action, the reason, the status, the decision
/// reason, the settler and the plan hash the owner was shown. A pending record
/// has no settler and an empty decision reason; a denied, granted or expired
/// record stays on the list with its settler. A read stores nothing and spends
/// nothing: a second read returns the same list and the live grants stay as
/// they were.
pub fn read_shown_requests(
    stand_in: &StandIn,
    caller: Caller<'_>,
    session: Option<&str>,
) -> Result<Value, (u16, String)> {
    stand_in.get_capability_requests(caller, session)
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
    /// `get_capsules` for the count, `admit_resident` for the signed fixture,
    /// `post_capsules` for its CID and `finish_start`. This mints no grant.
    ///
    /// `caller` is the authenticated caller, a method argument. This journey
    /// passes it to the list route and the launch route unchanged and does not
    /// judge it, so each route's own shell-only check runs before the body is
    /// read: a client caller is refused at the list route, before this journey
    /// reads the count or admits anything, and nothing is stored.
    ///
    /// The stand-in keeps one admitted row per lab CID, so a session after the
    /// first admits the same fixture files with one changed byte through
    /// `SignedBundle::distinct`: another lab CID, another row, the same asks.
    /// A fresh stand-in admits the plain fixture, so the first session is
    /// unchanged. The capsule list is the stand-in's own read of how many
    /// sessions it holds; this journey adds no second launch path.
    pub fn running_agent(
        stand_in: &mut StandIn,
        caller: Caller<'_>,
    ) -> Result<String, (u16, String)> {
        let sessions = stand_in.get_capsules(caller)?["capsules"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(0);
        let bundle = if sessions == 0 {
            SignedBundle::new()
        } else {
            SignedBundle::distinct(&format!("agent-host-{sessions}"))
        };
        stand_in.admit_resident(
            bundle.path(),
            &bundle.signature(),
            bundle.accepted(),
            Start::Ok,
        )?;
        let launched = stand_in.post_capsules(caller, &bundle.launch_body())?;
        let id = launched["id"]
            .as_str()
            .expect("the stand-in names the launch")
            .to_owned();
        stand_in.finish_start(&id)?;
        Ok(id)
    }

    /// The agent asks for one plan through `post_capability_request`. The
    /// request id is the stand-in's own, not a fixture name.
    ///
    /// `caller` is the authenticated caller, a method argument. This helper
    /// passes it to the request route unchanged and does not judge it, so the
    /// route's own caller check runs before the body is read: a shell caller is
    /// refused and stores nothing, whether the plan is `PLAN_A`, `PLAN_B` or
    /// empty bytes.
    ///
    /// `resource`, `action` and `reason` are the ask the agent names, method
    /// arguments too. This helper sends all three unchanged as the route's
    /// `resource`, `action` and `reason` keys and passes them through, so the
    /// route's own scheme, action and declared-ask checks decide the answer: a
    /// resource without `elastos://` or `localhost://`, an action outside the
    /// route's list, and a pair the signed bundle did not declare are each
    /// refused and store nothing. The `plan` key is `preview` of those bytes.
    /// Ok is the route's `request_id`. The reason is text on the request; the
    /// route stores it as given and mints no grant from it. An empty reason is
    /// stored as `""`.
    pub fn request(
        stand_in: &mut StandIn,
        caller: Caller<'_>,
        plan: &[u8],
        resource: &str,
        action: &str,
        reason: &str,
    ) -> Result<String, (u16, String)> {
        let hash = preview(stand_in, plan).sha256;
        let stored = stand_in.post_capability_request(
            caller,
            &json!({
                "resource": resource,
                "action": action,
                "reason": reason,
                "plan": hash,
            }),
        )?;
        Ok(stored["request_id"]
            .as_str()
            .expect("the route names the request")
            .to_owned())
    }
}

#[cfg(test)]
#[test]
fn a_grant_bound_to_one_plan_is_refused_for_another_plan() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");

    let request_a = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let request_b = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_ne!(
        request_a, request_b,
        "two plans are two requests, so the two grants differ"
    );

    // The owner approves plan A with grant G1 and plan B with grant G2,
    // naming the hash the shell's request view shows in `plan`.
    let owner_sees_a = plan_sha256(PLAN_A);
    let owner_sees_b = plan_sha256(PLAN_B);
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &request_a,
            "once",
            &owner_sees_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner approves plan A"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &request_b,
            "once",
            &owner_sees_b,
            "owner approved"
        ),
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
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &request_b,
            PLAN_A
        ),
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
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &request_a,
            PLAN_A
        ),
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
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &request_b,
            PLAN_B
        ),
        Ok(json!({ "valid": true })),
        "spending G1 left G2's own plan use intact"
    );
}

#[cfg(test)]
#[test]
fn deny_one_shown_step() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
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

    fn running_without_cause(stand_in: &StandIn, id: &str) -> Value {
        let listed = capsule(stand_in, id);
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let mut stand_in = StandIn::new();

    assert_eq!(
        deny_shown_plan(
            &mut stand_in,
            Caller::Shell,
            "req-absent",
            "deny the shown plan"
        ),
        Err((400, "unknown request: req-absent".to_owned())),
        "a deny of an absent request settles nothing and names the id"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        json!({ "capsules": [] }),
        "the refused deny leaves no instance in the capsule list"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused deny mints no grant"
    );

    // The one launch journey makes the running session the shown steps come
    // from. It mints no grant.
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        session, "component-1",
        "the fresh stand-in names the one running session component-1"
    );
    assert_eq!(
        running_without_cause(&stand_in, &session),
        json!({ "id": "component-1", "status": "running", "cause": "" }),
        "the shown plan comes from a running session with no cause"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_a.len(),
        64,
        "the shown hash of plan A is 64 lowercase hex characters"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "the shown hash of plan B is 64 lowercase hex characters"
    );

    // Both steps come from the one submit call, as the session.
    let denied = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the first pending request");
    assert_eq!(
        denied, "request-1",
        "the session's first shown step is the stand-in's first request"
    );
    let sibling = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the second pending request");
    assert_eq!(
        sibling, "request-2",
        "the session's second shown step is the stand-in's second request"
    );

    let denied_pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &session, &denied),
        denied_pending,
        "the first shown step is pending with its plan hash and no decision"
    );
    let sibling_pending = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &session, &sibling),
        sibling_pending,
        "the second shown step is pending with its plan hash and no decision"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a pending shown step is not a live grant"
    );

    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, &denied, "deny the shown plan"),
        Ok(json!({ "success": true })),
        "the shell denies the first shown step"
    );
    assert_eq!(
        record(&stand_in, &session, &denied),
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "denied",
            "decision_reason": "deny the shown plan",
            "settled_by": "shell",
            "plan": plan_a,
        }),
        "the denied step stores the shell reason and settler"
    );
    assert_eq!(
        record(&stand_in, &session, &sibling),
        sibling_pending,
        "a shell deny settles one shown step and the sibling stays pending"
    );
    assert_eq!(
        running_without_cause(&stand_in, &session),
        json!({ "id": "component-1", "status": "running", "cause": "" }),
        "a shell deny leaves the session running with no cause"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a denied step is not a live grant"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &denied,
            PLAN_A
        ),
        Err((400, "unknown grant".to_owned())),
        "running a denied step is refused with unknown grant, without an id"
    );

    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &denied,
            "once",
            &plan_a,
            "owner approved"
        ),
        Err((400, "request is not pending: request-1".to_owned())),
        "a denied step cannot be granted later"
    );
    assert_eq!(
        record(&stand_in, &session, &sibling),
        sibling_pending,
        "the refused late grant leaves the sibling pending"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused late grant mints nothing"
    );

    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &sibling,
            "once",
            &plan_b,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the sibling stays pending, so its own allow-once grant succeeds"
    );
    let allowed = vec![json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    })];
    assert_eq!(live(&stand_in), allowed, "only the sibling grant is live");

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &denied,
            PLAN_A
        ),
        Err((400, "unknown grant".to_owned())),
        "the denied step still has no grant after its sibling is granted"
    );
    assert_eq!(
        live(&stand_in),
        allowed,
        "the refused denied-step use leaves the sibling grant live"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &sibling,
            PLAN_B
        ),
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
fn agent_cannot_deny_its_own_shown_plan() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    fn shell_refusal() -> Result<Value, (u16, String)> {
        Err((403, "This endpoint requires shell privileges".to_owned()))
    }

    let mut stand_in = StandIn::new();

    let absent = deny_shown_plan(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-absent",
        "deny the shown plan",
    );
    assert_eq!(
        absent,
        shell_refusal(),
        "the agent that showed the plan cannot deny it: a client deny runs before the request lookup, so even an absent id is the shell refusal"
    );
    assert_ne!(
        absent,
        Err((400, "unknown request: request-absent".to_owned())),
        "the client deny is refused before the deny body is read, so it never reports an unknown request"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        json!({ "capsules": [] }),
        "the refused client deny leaves no instance in the capsule list"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused client deny mints no grant"
    );

    // Two running sessions: the agent that posts the plans and the other
    // session that must not settle them.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "the second running session is the stand-in's next component"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_a.len(),
        64,
        "the shown hash of plan A is 64 lowercase hex characters"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "the shown hash of plan B is 64 lowercase hex characters"
    );

    let denied = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the first shown plan");
    assert_eq!(
        denied, "request-1",
        "the first session's shown plan is the stand-in's first request"
    );
    let sibling = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the second shown plan");
    assert_eq!(
        sibling, "request-2",
        "the first session's second shown plan is the stand-in's second request"
    );

    let denied_pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let sibling_pending = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });

    // The posting session and the other running session both fail to deny
    // either shown plan, and a missing id is that same refusal.
    for (session_id, request_id) in [
        ("component-1", "request-1"),
        ("component-2", "request-1"),
        ("component-1", "request-2"),
        ("component-1", "request-absent"),
    ] {
        let refused = deny_shown_plan(
            &mut stand_in,
            Caller::Client { session_id },
            request_id,
            "deny the shown plan",
        );
        assert_eq!(
            refused,
            shell_refusal(),
            "the agent that showed the plan cannot deny it: the client caller {session_id} with {request_id} is refused as a shell-only route before the deny body is read"
        );
        assert_ne!(
            refused,
            Err((400, "unknown request: request-absent".to_owned())),
            "the client deny with {request_id} as {session_id} is not an unknown request"
        );
        assert_ne!(
            refused,
            Err((400, "unknown request: request-1".to_owned())),
            "the client deny with {request_id} as {session_id} is not an unknown request"
        );
        assert_ne!(
            refused,
            Err((400, "request is not pending: request-1".to_owned())),
            "the client deny with {request_id} as {session_id} is not a settled request"
        );
        assert_ne!(
            refused,
            Err((400, "request is not pending: request-2".to_owned())),
            "the client deny with {request_id} as {session_id} is not a settled request"
        );
        assert_eq!(
            record(&stand_in, &first, "request-1"),
            denied_pending,
            "the refused client deny with {request_id} as {session_id} leaves the first shown plan pending"
        );
        assert_eq!(
            record(&stand_in, &first, "request-2"),
            sibling_pending,
            "the refused client deny with {request_id} as {session_id} leaves the second shown plan pending"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the refused client deny with {request_id} as {session_id} mints no grant"
        );
    }

    assert_eq!(
        deny_shown_plan(
            &mut stand_in,
            Caller::Shell,
            "request-absent",
            "deny the shown plan"
        ),
        Err((400, "unknown request: request-absent".to_owned())),
        "the shell's deny of an absent request names the id and settles nothing"
    );
    assert_eq!(
        record(&stand_in, &first, "request-1"),
        denied_pending,
        "the shell's absent-id deny leaves the first shown plan pending"
    );
    assert_eq!(
        record(&stand_in, &first, "request-2"),
        sibling_pending,
        "the shell's absent-id deny leaves the second shown plan pending"
    );

    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, &denied, "deny the shown plan"),
        Ok(json!({ "success": true })),
        "the shell's deny settles the one shown step the agent could not deny"
    );
    let denied_record = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "denied",
        "decision_reason": "deny the shown plan",
        "settled_by": "shell",
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &denied),
        denied_record,
        "the shell's deny stores the one shown step as denied under the shell"
    );
    assert_eq!(
        record(&stand_in, &first, &sibling),
        sibling_pending,
        "the shell's deny leaves the sibling pending for its own allow-once use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a denied step is not a live grant"
    );

    let late = deny_shown_plan(
        &mut stand_in,
        Caller::Client { session_id: &first },
        &denied,
        "deny the shown plan",
    );
    assert_eq!(
        late,
        shell_refusal(),
        "the agent that showed the plan cannot deny it: the client deny after the shell's settlement is still the shell refusal"
    );
    assert_ne!(
        late,
        Err((400, "request is not pending: request-1".to_owned())),
        "the client deny after the settlement never reports a settled request"
    );
    assert_eq!(
        record(&stand_in, &first, &denied),
        denied_record,
        "the refused late client deny leaves the shell's settlement in place"
    );

    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &sibling,
            "once",
            &plan_b,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the sibling stays pending, so the shell's allow-once grant succeeds"
    );
    let allowed = vec![json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    })];
    assert_eq!(
        live(&stand_in),
        allowed,
        "only the sibling's allow-once grant is live"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &denied,
            PLAN_A
        ),
        Err((400, "unknown grant".to_owned())),
        "running the denied step is refused with unknown grant, without an id"
    );
    assert_eq!(
        live(&stand_in),
        allowed,
        "the refused denied-step use leaves the sibling grant live"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &sibling,
            PLAN_B
        ),
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
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        session, "component-1",
        "the fresh stand-in names the one session component-1"
    );

    let unanswered = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        unanswered, "request-1",
        "the agent's first shown step is the stand-in's first request"
    );
    let allowed = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
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
        approve(
            &mut stand_in,
            Caller::Shell,
            &allowed,
            "once",
            &plan_b,
            "owner approved"
        ),
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
        approve(
            &mut stand_in,
            Caller::Shell,
            &unanswered,
            "once",
            &plan_a,
            "owner approved"
        ),
        Err((400, "request is not pending: request-1".to_owned())),
        "an expired shown step cannot be granted later"
    );
    assert_eq!(
        live(&stand_in),
        allowed_live,
        "the refused late grant of the expired step mints nothing and the allowed step stays a grant"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &unanswered,
            PLAN_A
        ),
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
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &allowed,
            PLAN_B
        ),
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
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            "component-absent",
            "stop the shown session"
        ),
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
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
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
    let pending_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let allowed_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let other_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &second,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
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
        approve(
            &mut stand_in,
            Caller::Shell,
            &allowed_step,
            "once",
            &plan_b,
            "owner approved"
        ),
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
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            &first,
            "stop the shown session"
        ),
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
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &allowed_step,
            PLAN_B
        ),
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
        approve(
            &mut stand_in,
            Caller::Shell,
            &other_step,
            "once",
            &plan_a,
            "owner approved"
        ),
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
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second
            },
            &other_step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the other session's allow-once grant authorises its own use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the other session's once grant is spent by its one use"
    );

    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            &first,
            "stop the shown session"
        ),
        Err((400, "instance is not live: stopped".to_owned())),
        "a stop of an already stopped session refuses with its status"
    );
}

#[cfg(test)]
#[test]
fn shown_allow_once_expires() {
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

    fn is_live(stand_in: &StandIn, request_id: &str) -> bool {
        live(stand_in)
            .iter()
            .any(|entry| entry["request_id"] == request_id)
    }

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        session, "component-1",
        "the fresh stand-in names the one session component-1"
    );

    let spent_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let unspent_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        spent_step, "request-1",
        "the agent's first shown step is the stand-in's first request"
    );
    assert_eq!(
        unspent_step, "request-2",
        "the agent's second shown step is the stand-in's second request"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);

    // The owner allows each shown step once, through the one grant call.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &spent_step,
            "once",
            &plan_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the first shown step once"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &unspent_step,
            "once",
            &plan_b,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the second shown step once"
    );

    let granted = vec![
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "granted",
            "decision_reason": "owner approved",
            "settled_by": "shell",
            "plan": plan_a,
        }),
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
    ];
    assert_eq!(
        shown(&stand_in, &session),
        granted,
        "both allowed steps stay granted under the shell with the plan hash they posted"
    );

    let two_live = vec![
        json!({
            "request_id": "request-1",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }),
        json!({
            "request_id": "request-2",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }),
    ];
    assert_eq!(
        live(&stand_in),
        two_live,
        "the owner's two allow-once grants are the two live grants, request-1 then request-2"
    );

    // The first allow-once grant authorises exactly its own one use and is
    // then spent; the second stays unspent and live.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &spent_step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the first allow-once grant authorises its own one use"
    );
    let one_live = vec![two_live[1].clone()];
    assert_eq!(
        live(&stand_in),
        one_live,
        "the spent step leaves the live list and the unspent allow-once stays"
    );

    // Find the stand-in's own grant lifetime. The test names no instant: it
    // ages the stand-in through `age_shown_plan` and remembers only the last
    // instant it saw the unspent grant live.
    let mut last_live = 0;
    let mut probe = 1;
    for _ in 0..24 {
        age_shown_plan(&mut stand_in, probe);
        if !is_live(&stand_in, "request-2") {
            break;
        }
        last_live = probe;
        probe = probe.saturating_mul(2);
    }
    assert!(
        !is_live(&stand_in, "request-2"),
        "the unspent allow-once left the live list"
    );

    let mut due = last_live + 1;
    while due <= probe {
        age_shown_plan(&mut stand_in, due);
        if !is_live(&stand_in, "request-2") {
            break;
        }
        due += 1;
    }
    assert!(
        due <= probe,
        "the walk from the last live instant reaches the absent instant"
    );

    // One second before the stand-in's own lifetime the unspent grant is live
    // again, because the compare reads the stored instant.
    age_shown_plan(&mut stand_in, due - 1);
    assert_eq!(
        live(&stand_in),
        one_live,
        "one second before the stand-in's lifetime the unspent allow-once is live again"
    );
    assert_eq!(
        shown(&stand_in, &session),
        granted,
        "both allowed steps stay granted under the shell after the walk"
    );

    age_shown_plan(&mut stand_in, due);
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "an unused allow-once expires at the stand-in's grant lifetime and leaves the live list"
    );
    assert_eq!(
        shown(&stand_in, &session),
        granted,
        "the expiry of the unspent allow-once leaves both requests granted under the shell"
    );

    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &session }, &unspent_step, PLAN_B),
        Err((400, "grant is not live: Expired".to_owned())),
        "an unused allow-once expires at the stand-in's grant lifetime, so its use is refused as Expired"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused use of the expired allow-once mints nothing"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &spent_step,
            PLAN_A
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the spent step stays exhausted at the stand-in's grant lifetime"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the spent step stays exhausted and adds no live grant"
    );
}

#[cfg(test)]
#[test]
fn shown_session_lasts_until_stop() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    let live = |stand_in: &StandIn| -> Vec<Value> {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .as_array()
            .cloned()
            .expect("the shell live list holds a capabilities array")
    };

    let shown = |stand_in: &StandIn, session: &str| -> Vec<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
    };

    let record = |stand_in: &StandIn, session: &str, request_id: &str| -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    };

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        session, "component-1",
        "the fresh stand-in names the one session component-1"
    );

    let session_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let once_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let refused_word = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        session_step, "request-1",
        "the agent's first shown step is the stand-in's first request"
    );
    assert_eq!(
        once_step, "request-2",
        "the agent's second shown step is the stand-in's second request"
    );
    assert_eq!(
        refused_word, "request-3",
        "the agent's third shown step is the stand-in's third request"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);

    // Another duration word reaches the stand-in's own refusal and mints
    // nothing, so that shown step stays pending with its plan hash.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &refused_word,
            "standing",
            &plan_a,
            "owner approved"
        ),
        Err((
            400,
            "Invalid duration: standing. Expected 'once' or 'session'".to_owned()
        )),
        "a shown step allowed for standing is refused with the stand-in's invalid-duration reason"
    );
    assert_eq!(
        record(&stand_in, &session, &refused_word),
        json!({
            "request_id": "request-3",
            "session_id": "component-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "reason": "",
            "status": "pending",
            "decision_reason": "",
            "settled_by": null,
            "plan": plan_a,
        }),
        "the refused duration word leaves that shown step pending with the plan hash it posted"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused duration word mints no live grant"
    );

    // The owner allows the first shown step for this session and the second
    // once, through the one grant call, naming the hashes they saw.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &session_step,
            "session",
            &plan_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the first shown step for this session"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &once_step,
            "once",
            &plan_b,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the second shown step once"
    );

    let granted_session = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let granted_once = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &session, &session_step),
        granted_session,
        "the session step is granted under the shell with the hash of plan A"
    );
    assert_eq!(
        record(&stand_in, &session, &once_step),
        granted_once,
        "the allow-once step is granted under the shell with the hash of plan B"
    );

    let session_live = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "session",
        "granted_at": 0,
    });
    let once_live = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let both_live = vec![session_live.clone(), once_live.clone()];
    assert_eq!(
        live(&stand_in),
        both_live,
        "the session step and the allow-once step are the two live grants, request-1 then request-2"
    );

    // Find the stand-in's own once lifetime. The test names no instant: it
    // ages the stand-in through `age_shown_plan` and remembers only the last
    // instant it saw the allow-once witness live.
    let mut last_live = 0;
    let mut probe = 1;
    for _ in 0..24 {
        age_shown_plan(&mut stand_in, probe);
        if !live(&stand_in)
            .iter()
            .any(|entry| entry["request_id"] == "request-2")
        {
            break;
        }
        last_live = probe;
        probe = probe.saturating_mul(2);
    }
    assert!(
        !live(&stand_in)
            .iter()
            .any(|entry| entry["request_id"] == "request-2"),
        "the once witness left the live list"
    );

    let mut due = last_live + 1;
    while due <= probe {
        age_shown_plan(&mut stand_in, due);
        if !live(&stand_in)
            .iter()
            .any(|entry| entry["request_id"] == "request-2")
        {
            break;
        }
        due += 1;
    }
    assert!(
        due <= probe,
        "the walk from the last live instant reaches the absent instant"
    );

    // One second before the stand-in's once lifetime the allow-once witness
    // is live again, and the session grant was never due.
    age_shown_plan(&mut stand_in, due - 1);
    assert_eq!(
        live(&stand_in),
        both_live,
        "one second before the stand-in's once lifetime both grants are live with their own durations"
    );

    age_shown_plan(&mut stand_in, due);
    assert_eq!(
        live(&stand_in),
        vec![session_live.clone()],
        "the allow-once step leaves the live list and the session step stays live with duration session"
    );
    assert_eq!(
        record(&stand_in, &session, &session_step),
        granted_session,
        "the session step stays granted with the hash of plan A after the once lifetime"
    );
    assert_eq!(
        record(&stand_in, &session, &once_step),
        granted_once,
        "the allow-once step stays granted with the hash of plan B after its own lifetime"
    );

    // A session grant authorises its bound plan again and again, and a
    // different plan is refused without spending it.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &session_step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the session grant authorises its bound plan"
    );
    assert_eq!(
        live(&stand_in),
        vec![session_live.clone()],
        "the used session grant stays on the live list"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &session_step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the session grant authorises its bound plan a second time"
    );
    assert_eq!(
        live(&stand_in),
        vec![session_live.clone()],
        "two uses of its plan leave the session grant live"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &session_step,
            PLAN_B
        ),
        Err((403, "grant is not bound to this plan".to_owned())),
        "a different plan is refused with grant is not bound to this plan"
    );
    assert_eq!(
        live(&stand_in),
        vec![session_live.clone()],
        "the refused different plan leaves the session grant live"
    );

    // The stop revokes that session's live grant; the record stays granted.
    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            "component-1",
            "stop the shown session"
        ),
        Ok(Value::Null),
        "the stop of that session reports its settlement"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a session grant lasts until that session stops"
    );
    let stopped = record(&stand_in, &session, &session_step);
    assert_eq!(
        stopped["status"], "granted",
        "the stopped session's grant record stays granted"
    );
    assert_eq!(
        stopped["settled_by"], "shell",
        "the stopped session's grant record keeps the shell as settler"
    );
    assert_eq!(
        stopped["decision_reason"], "owner approved",
        "the stopped session's grant record keeps the owner's decision reason"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &session_step,
            PLAN_A
        ),
        Err((400, "grant is not live: Revoked".to_owned())),
        "the stopped session's grant is revoked, so its use is refused as Revoked"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused use of the revoked grant mints nothing"
    );
}

#[cfg(test)]
#[test]
fn shown_grant_authorises_only_its_session() {
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

    fn client_live(stand_in: &StandIn, session: &str) -> Value {
        stand_in
            .get_capability_list(
                Caller::Client {
                    session_id: session,
                },
                None,
            )
            .expect("the client live list")
    }

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let mut stand_in = StandIn::new();
    let first_session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second_session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first_session, "component-1",
        "a shown grant authorises only its session: the fresh stand-in names its first session component-1"
    );
    assert_eq!(
        second_session, "component-2",
        "a shown grant authorises only its session: the stand-in names its second session component-2"
    );

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &first_session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &second_session,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown grant authorises only its session: the first session's step is request-1"
    );
    assert_eq!(
        second_step, "request-2",
        "a shown grant authorises only its session: the second session's step is request-2"
    );

    // The owner allows each shown step once, through the one grant call,
    // naming the hash that request posted.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &first_step,
            "once",
            &plan_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "a shown grant authorises only its session: the owner allows the first session's step once"
    );
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &second_step, "once", &plan_b, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown grant authorises only its session: the owner allows the second session's step once"
    );

    let granted_first = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let granted_second = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &first_session, &first_step),
        granted_first,
        "a shown grant authorises only its session: the first step is granted under the shell with the hash of plan A"
    );
    assert_eq!(
        record(&stand_in, &second_session, &second_step),
        granted_second,
        "a shown grant authorises only its session: the second step is granted under the shell with the hash of plan B"
    );

    let live_first = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let live_second = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let both_live = vec![live_first.clone(), live_second.clone()];
    assert_eq!(
        live(&stand_in),
        both_live,
        "a shown grant authorises only its session: the shell live list has both once grants, request-1 then request-2"
    );

    let client_first = json!({
        "capabilities": [{
            "request_id": "request-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }],
    });
    let client_second = json!({
        "capabilities": [{
            "request_id": "request-2",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }],
    });
    assert_eq!(
        client_live(&stand_in, &first_session),
        client_first,
        "a shown grant authorises only its session: the first session's live list holds request-1 alone and omits session_id"
    );
    assert_eq!(
        client_live(&stand_in, &second_session),
        client_second,
        "a shown grant authorises only its session: the second session's live list holds request-2 alone and omits session_id"
    );

    // Each session uses the other session's shown grant. The use is refused
    // before any spend, so both grants stay live.
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: "component-2" }, &first_step, PLAN_A),
        Err((
            403,
            "wrong capsule: expected component-1, got component-2".to_owned()
        )),
        "a shown grant authorises only its session: the second session's use of request-1 is refused"
    );
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &first_session }, &second_step, PLAN_B),
        Err((
            403,
            "wrong capsule: expected component-2, got component-1".to_owned()
        )),
        "a shown grant authorises only its session: the first session's use of request-2 is refused"
    );

    assert_eq!(
        live(&stand_in),
        both_live,
        "a shown grant authorises only its session: after both refused uses the shell live list is unchanged byte for byte"
    );
    assert_eq!(
        client_live(&stand_in, &first_session),
        client_first,
        "a shown grant authorises only its session: the first session's live list is unchanged"
    );
    assert_eq!(
        client_live(&stand_in, &second_session),
        client_second,
        "a shown grant authorises only its session: the second session's live list is unchanged"
    );
    assert_eq!(
        record(&stand_in, &first_session, &first_step),
        granted_first,
        "a shown grant authorises only its session: the first request stays granted with the hash of plan A"
    );
    assert_eq!(
        record(&stand_in, &second_session, &second_step),
        granted_second,
        "a shown grant authorises only its session: the second request stays granted with the hash of plan B"
    );

    // Each session's own use of its own grant still runs and spends it.
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &first_session }, &first_step, PLAN_A),
        Ok(json!({ "valid": true })),
        "a shown grant authorises only its session: the first session's own use of request-1 still runs"
    );
    assert_eq!(
        live(&stand_in),
        vec![live_second.clone()],
        "a shown grant authorises only its session: the spent first grant leaves the live list and the second grant stays"
    );
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &second_session }, &second_step, PLAN_B),
        Ok(json!({ "valid": true })),
        "a shown grant authorises only its session: the second session's own use of request-2 still runs"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown grant authorises only its session: both once grants left the live list"
    );
    assert_eq!(
        record(&stand_in, &first_session, &first_step),
        granted_first,
        "a shown grant authorises only its session: the first request stays granted under the shell with the owner's decision"
    );
    assert_eq!(
        record(&stand_in, &second_session, &second_step),
        granted_second,
        "a shown grant authorises only its session: the second request stays granted under the shell with the owner's decision"
    );
}

#[cfg(test)]
#[test]
fn owner_approves_only_the_shown_hash() {
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let mut stand_in = StandIn::new();
    let session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        session, "component-1",
        "the owner grant mints only the hash the shown request stored: the fresh stand-in names its session component-1"
    );

    let step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        step, "request-1",
        "the owner grant mints only the hash the shown request stored: the agent's first step is request-1"
    );

    let shown = plan_sha256(PLAN_A);
    assert_eq!(
        shown.len(),
        64,
        "the owner grant mints only the hash the shown request stored: the shown hash is 64 lowercase hex characters"
    );

    // The shell's request view shows the plan hash the request stored. The
    // owner's card carries a hash to compare with that one value.
    let pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": Value::Null,
        "plan": shown,
    });
    assert_eq!(
        record(&stand_in, &session, &step),
        pending,
        "the owner grant mints only the hash the shown request stored: the agent's request stays pending with the hash of plan A"
    );

    // Another plan, an empty hash and a truncated hash are each not the hash
    // the shown request stored. Each refusal mints nothing.
    let refused = Err((
        403,
        "approved plan does not match the requested plan".to_owned(),
    ));
    let candidates = [plan_sha256(PLAN_B), String::new(), shown[..63].to_owned()];
    for candidate in &candidates {
        assert_eq!(
            approve(&mut stand_in, Caller::Shell, &step, "once", candidate, "owner approved"),
            refused,
            "the owner grant mints only the hash the shown request stored: the owner's approval with a hash other than {shown} is refused"
        );
        assert_eq!(
            record(&stand_in, &session, &step),
            pending,
            "the owner grant mints only the hash the shown request stored: the request stays pending after the refused hash {candidate:?}"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the owner grant mints only the hash the shown request stored: the refused hash {candidate:?} mints no grant"
        );
    }

    // A refused approval leaves nothing to run.
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &session }, &step, PLAN_A),
        Err((400, "unknown grant".to_owned())),
        "the owner grant mints only the hash the shown request stored: running the request before the owner grants it is refused as unknown grant"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the owner grant mints only the hash the shown request stored: the refused use mints nothing"
    );

    // The exact hash mints one grant for one use.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &step, "once", &shown, "owner approved"),
        Ok(json!({ "success": true })),
        "the owner grant mints only the hash the shown request stored: the owner's approval with the stored hash is accepted"
    );
    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": shown,
    });
    assert_eq!(
        record(&stand_in, &session, &step),
        granted,
        "the owner grant mints only the hash the shown request stored: the request is granted under the shell with the hash of plan A"
    );
    let live_one = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![live_one],
        "the owner grant mints only the hash the shown request stored: the exact hash stores one once grant"
    );

    // The grant runs for the plan it is bound to and spends one use.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &session
            },
            &step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the owner grant mints only the hash the shown request stored: the granted plan runs once"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the owner grant mints only the hash the shown request stored: the spent once grant leaves the live list"
    );
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &session }, &step, PLAN_A),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the owner grant mints only the hash the shown request stored: a second use of the same plan is refused as Exhausted"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the owner grant mints only the hash the shown request stored: the refused second use leaves the live list empty"
    );
}

#[cfg(test)]
#[test]
fn agent_cannot_approve_its_own_shown_plan() {
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let mut stand_in = StandIn::new();
    let poster = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let other = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        poster, "component-1",
        "the agent that showed the plan cannot mint its grant: the fresh stand-in names the session that posts the plan component-1"
    );
    assert_eq!(
        other, "component-2",
        "the agent that showed the plan cannot mint its grant: the stand-in names the other running session component-2"
    );

    let step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &poster,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        step, "request-1",
        "the agent that showed the plan cannot mint its grant: the posted plan is request-1"
    );

    let shown = plan_sha256(PLAN_A);
    assert_eq!(
        shown.len(),
        64,
        "the agent that showed the plan cannot mint its grant: the shown hash is 64 lowercase hex characters"
    );

    // The shell's request view shows the pending step with the posted hash.
    let pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": Value::Null,
        "plan": shown,
    });
    assert_eq!(
        record(&stand_in, &poster, &step),
        pending,
        "the agent that showed the plan cannot mint its grant: the posted plan stays pending with its hash before any approval"
    );

    // Six client calls: the posting session's exact hash, another plan, an
    // empty hash, a truncated hash, an unknown duration word, and the other
    // running session's exact hash. The shell-only route refuses each before
    // it reads the body, so none of them reaches the hash or duration check.
    let refused = Err((403, "This endpoint requires shell privileges".to_owned()));
    let calls = [
        (
            Caller::Client {
                session_id: &poster,
            },
            "once",
            plan_sha256(PLAN_A),
        ),
        (
            Caller::Client {
                session_id: &poster,
            },
            "once",
            plan_sha256(PLAN_B),
        ),
        (
            Caller::Client {
                session_id: &poster,
            },
            "once",
            String::new(),
        ),
        (
            Caller::Client {
                session_id: &poster,
            },
            "once",
            shown[..63].to_owned(),
        ),
        (
            Caller::Client {
                session_id: &poster,
            },
            "standing",
            plan_sha256(PLAN_A),
        ),
        (
            Caller::Client { session_id: &other },
            "once",
            plan_sha256(PLAN_A),
        ),
    ];
    for (caller, duration, candidate) in calls {
        let result = approve(
            &mut stand_in,
            caller,
            &step,
            duration,
            &candidate,
            "owner approved",
        );
        assert_eq!(
            result, refused,
            "the agent that showed the plan cannot mint its grant: the client's approval with duration {duration} and hash {candidate:?} is refused as a client on a shell-only route"
        );
        assert_ne!(
            result,
            Err((
                403,
                "approved plan does not match the requested plan".to_owned()
            )),
            "the agent that showed the plan cannot mint its grant: the client refusal runs before the hash check, so {candidate:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((
                400,
                "Invalid duration: standing. Expected 'once' or 'session'".to_owned()
            )),
            "the agent that showed the plan cannot mint its grant: the client refusal runs before the duration check, so {duration} never reaches it"
        );
        assert_eq!(
            record(&stand_in, &poster, &step),
            pending,
            "the agent that showed the plan cannot mint its grant: the client's approval with duration {duration} and hash {candidate:?} leaves request-1 pending with the posted hash"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the agent that showed the plan cannot mint its grant: the client's approval with duration {duration} and hash {candidate:?} mints no grant"
        );
    }

    // No client approval left anything to run.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &poster
            },
            &step,
            PLAN_A
        ),
        Err((400, "unknown grant".to_owned())),
        "the agent that showed the plan cannot mint its grant: the posted plan has no grant to run"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent that showed the plan cannot mint its grant: the refused client use leaves the live list empty"
    );

    // The shell's own call with the shown hash mints one use.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &step, "once", &shown, "owner approved"),
        Ok(json!({ "success": true })),
        "the agent that showed the plan cannot mint its grant: the shell's approval with the shown hash is accepted"
    );
    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": shown,
    });
    assert_eq!(
        record(&stand_in, &poster, &step),
        granted,
        "the agent that showed the plan cannot mint its grant: the shell's approval settles the request with the posted hash"
    );
    let live_one = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![live_one],
        "the agent that showed the plan cannot mint its grant: the shell's approval stores one once grant"
    );

    // The shell's grant authorises the posted plan's one use.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &poster
            },
            &step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the agent that showed the plan cannot mint its grant: the granted plan runs once"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent that showed the plan cannot mint its grant: the spent once grant leaves the live list"
    );
    assert_eq!(
        execute(&mut stand_in, Caller::Client { session_id: &poster }, &step, PLAN_A),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the agent that showed the plan cannot mint its grant: a second use of the same plan is refused as Exhausted"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent that showed the plan cannot mint its grant: the refused second use leaves the live list empty"
    );
}

#[cfg(test)]
#[test]
fn shell_cannot_spend_a_shown_grant() {
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let mut stand_in = StandIn::new();
    let owner_session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let other_session = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        owner_session, "component-1",
        "the shell cannot spend a shown grant: the fresh stand-in names its first session component-1"
    );
    assert_eq!(
        other_session, "component-2",
        "the shell cannot spend a shown grant: the stand-in names its second session component-2"
    );

    let step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &owner_session,
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        step, "request-1",
        "the shell cannot spend a shown grant: the shown plan is request-1"
    );

    let shown = plan_sha256(PLAN_A);
    assert_eq!(
        shown.len(),
        64,
        "the shell cannot spend a shown grant: the shown hash is 64 lowercase hex characters"
    );

    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &step, "once", &shown, "owner approved"),
        Ok(json!({ "success": true })),
        "the shell cannot spend a shown grant: the owner's approval with the shown hash is accepted"
    );

    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": shown,
    });
    assert_eq!(
        record(&stand_in, &owner_session, &step),
        granted,
        "the shell cannot spend a shown grant: the owner's approval settles request-1 under the shell with the shown hash"
    );

    let live_one = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![live_one.clone()],
        "the shell cannot spend a shown grant: the shell's approval stores one once grant"
    );

    // Three shell calls: the bound plan, a different plan and empty plan
    // bytes. The use route refuses the shell before it reads the body, so
    // none of them reaches the plan check and the grant stays live.
    let refused = Err((
        403,
        "capability validate needs an instance session".to_owned(),
    ));
    let plans: [&[u8]; 3] = [PLAN_A, PLAN_B, b""];
    for plan in plans {
        let result = execute(&mut stand_in, Caller::Shell, &step, plan);
        assert_eq!(
            result, refused,
            "the shell cannot spend a shown grant: the shell's use of request-1 with plan bytes {plan:?} is refused as a shell on an instance-session route"
        );
        assert_ne!(
            result,
            Err((403, "grant is not bound to this plan".to_owned())),
            "the shell cannot spend a shown grant: the shell refusal runs before the plan check, so {plan:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((
                403,
                "wrong capsule: expected component-1, got component-2".to_owned()
            )),
            "the shell cannot spend a shown grant: the shell refusal runs before the session check, so {plan:?} never reaches it"
        );
        assert_eq!(
            record(&stand_in, &owner_session, &step),
            granted,
            "the shell cannot spend a shown grant: the shell's refused use with plan bytes {plan:?} leaves request-1 granted with the shown hash"
        );
        assert_eq!(
            live(&stand_in),
            vec![live_one.clone()],
            "the shell cannot spend a shown grant: the shell's refused use with plan bytes {plan:?} leaves the once grant live"
        );
    }

    // The other session's use is refused and spends nothing either.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &other_session,
            },
            &step,
            PLAN_A
        ),
        Err((
            403,
            "wrong capsule: expected component-1, got component-2".to_owned()
        )),
        "the shell cannot spend a shown grant: the other session's use of request-1 is refused"
    );
    assert_eq!(
        live(&stand_in),
        vec![live_one.clone()],
        "the shell cannot spend a shown grant: the other session's refused use leaves the once grant live"
    );
    assert_eq!(
        record(&stand_in, &owner_session, &step),
        granted,
        "the shell cannot spend a shown grant: the other session's refused use leaves request-1 granted"
    );

    // The owning session's own use runs once and spends the grant.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &owner_session,
            },
            &step,
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the shell cannot spend a shown grant: the owning session's own use of request-1 still runs"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot spend a shown grant: the spent once grant leaves the live list"
    );

    // A shell call after that spend is still the session refusal, so the
    // caller check runs before the life check.
    let after_spend = execute(&mut stand_in, Caller::Shell, &step, PLAN_A);
    assert_eq!(
        after_spend, refused,
        "the shell cannot spend a shown grant: a shell call after the spend is still refused as a shell"
    );
    assert_ne!(
        after_spend,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the shell cannot spend a shown grant: the caller check runs before the life check, so the spent grant never reports Exhausted to a shell"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot spend a shown grant: the refused shell use after the spend leaves the live list empty"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &owner_session,
            },
            &step,
            PLAN_A
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "the shell cannot spend a shown grant: a second use by the owning session is refused as Exhausted"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot spend a shown grant: the refused second use leaves the live list empty"
    );

    let settled = record(&stand_in, &owner_session, &step);
    assert_eq!(
        settled["status"], "granted",
        "the shell cannot spend a shown grant: request-1 stays granted"
    );
    assert_eq!(
        settled["settled_by"], "shell",
        "the shell cannot spend a shown grant: request-1 stays settled by the shell"
    );
    assert_eq!(
        settled["decision_reason"], "owner approved",
        "the shell cannot spend a shown grant: request-1 keeps the owner's decision reason"
    );
}

#[cfg(test)]
#[test]
fn shell_cannot_submit_a_shown_plan() {
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
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

    fn running_without_cause(stand_in: &StandIn, id: &str) -> Value {
        let listed = capsule(stand_in, id);
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let mut stand_in = StandIn::new();
    let refused = Err((
        403,
        "capability request needs an instance session".to_owned(),
    ));

    // The shell's submit on a fresh stand-in is the caller refusal. The
    // instance lookup runs only after the caller check, so no instance is
    // named and nothing is looked up.
    let fresh = request(
        &mut stand_in,
        Caller::Shell,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    );
    assert_eq!(
        fresh, refused,
        "the shell cannot submit a shown plan: the shell's submit of plan A on a fresh stand-in is refused as a caller without an instance session"
    );
    assert_ne!(
        fresh,
        Err((400, "unknown instance: component-1".to_owned())),
        "the shell cannot submit a shown plan: the caller check runs before the instance lookup, so the refused submit never reports an unknown instance"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        json!({ "capsules": [] }),
        "the shell cannot submit a shown plan: the refused submit mints no instance"
    );
    assert_eq!(
        shown(&stand_in, "component-1"),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the refused submit stores no request for component-1"
    );
    assert_eq!(
        shown(&stand_in, "component-2"),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the refused submit stores no request for component-2"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the refused submit mints no grant"
    );

    // Two sessions come from the one launch journey and stay running.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "the shell cannot submit a shown plan: the fresh stand-in names its first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "the shell cannot submit a shown plan: the stand-in names its second session component-2"
    );
    assert_eq!(
        running_without_cause(&stand_in, &first),
        json!({ "id": "component-1", "status": "running", "cause": "" }),
        "the shell cannot submit a shown plan: the first session runs with no cause"
    );
    assert_eq!(
        running_without_cause(&stand_in, &second),
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "the shell cannot submit a shown plan: the second session runs with no cause"
    );

    // Three shell calls: the shown plan, another plan and empty plan bytes.
    // The request route refuses the shell before it reads the body, so none
    // of them reaches an action, scheme or manifest check, and none is stored.
    let plans: [&[u8]; 3] = [PLAN_A, PLAN_B, b""];
    for plan in plans {
        let result = request(
            &mut stand_in,
            Caller::Shell,
            plan,
            "localhost://Public/plan-approval/a.txt",
            "read",
            "",
        );
        assert_eq!(
            result, refused,
            "the shell cannot submit a shown plan: the shell's submit with plan bytes {plan:?} is refused as a caller without an instance session"
        );
        assert_ne!(
            result,
            Err((
                403,
                "ask not declared in the signed manifest: localhost://Public/plan-approval/a.txt read".to_owned()
            )),
            "the shell cannot submit a shown plan: the caller refusal runs before the manifest check, so {plan:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((
                400,
                "Invalid action: read. Expected: read, write, execute, delete, message, admin"
                    .to_owned()
            )),
            "the shell cannot submit a shown plan: the caller refusal runs before the action check, so {plan:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((
                400,
                "Unsupported resource scheme. Allowed: elastos://, localhost://".to_owned()
            )),
            "the shell cannot submit a shown plan: the caller refusal runs before the scheme check, so {plan:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((400, "unknown instance: component-1".to_owned())),
            "the shell cannot submit a shown plan: the caller refusal runs before the instance lookup, so {plan:?} never reaches it"
        );
        assert_eq!(
            shown(&stand_in, "component-1"),
            Vec::<Value>::new(),
            "the shell cannot submit a shown plan: the shell's refused submit with plan bytes {plan:?} leaves component-1's request array empty"
        );
        assert_eq!(
            shown(&stand_in, "component-2"),
            Vec::<Value>::new(),
            "the shell cannot submit a shown plan: the shell's refused submit with plan bytes {plan:?} leaves component-2's request array empty"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the shell cannot submit a shown plan: the shell's refused submit with plan bytes {plan:?} leaves the live list empty"
        );
        assert_eq!(
            running_without_cause(&stand_in, &first),
            json!({ "id": "component-1", "status": "running", "cause": "" }),
            "the shell cannot submit a shown plan: the shell's refused submit with plan bytes {plan:?} leaves component-1 running with no cause"
        );
        assert_eq!(
            running_without_cause(&stand_in, &second),
            json!({ "id": "component-2", "status": "running", "cause": "" }),
            "the shell cannot submit a shown plan: the shell's refused submit with plan bytes {plan:?} leaves component-2 running with no cause"
        );
    }

    // The instance session's own submit stores one pending request.
    assert_eq!(
        request(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1"
            },
            PLAN_A,
            "localhost://Public/plan-approval/a.txt",
            "read",
            "",
        ),
        Ok("request-1".to_owned()),
        "the shell cannot submit a shown plan: the instance session's own submit stores the stand-in's first request"
    );

    let shown_hash = plan_sha256(PLAN_A);
    assert_eq!(
        shown_hash.len(),
        64,
        "the shell cannot submit a shown plan: the shown hash is 64 lowercase hex characters"
    );

    let pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": shown_hash,
    });
    assert_eq!(
        record(&stand_in, &first, "request-1"),
        pending,
        "the shell cannot submit a shown plan: the instance session's submit stores one pending request with the shown hash and no decision"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the pending request mints no grant"
    );

    // The shell grants the request the instance session submitted.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, "request-1", "once", &shown_hash, "owner approved"),
        Ok(json!({ "success": true })),
        "the shell cannot submit a shown plan: the owner's approval of request-1 with the shown hash is accepted"
    );

    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": shown_hash,
    });
    assert_eq!(
        record(&stand_in, &first, "request-1"),
        granted,
        "the shell cannot submit a shown plan: the shell's approval settles request-1 as granted under the shell with the shown hash"
    );

    let live_one = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![live_one.clone()],
        "the shell cannot submit a shown plan: the shell's approval stores one once grant for request-1"
    );

    // That session's own use runs once and spends the grant.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1"
            },
            "request-1",
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "the shell cannot submit a shown plan: the instance session's own use of request-1 runs"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the spent once grant leaves the live list"
    );

    // A shell submit after that spend is still the session refusal, so the
    // caller check runs before any request-state check.
    let after_spend = request(
        &mut stand_in,
        Caller::Shell,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    );
    assert_eq!(
        after_spend, refused,
        "the shell cannot submit a shown plan: a shell submit after the spend is still refused as a caller without an instance session"
    );
    assert_ne!(
        after_spend,
        Err((400, "request is not pending: request-1".to_owned())),
        "the shell cannot submit a shown plan: the caller check runs before the request-state check, so the spent request never reports not pending to a shell"
    );
    assert_ne!(
        after_spend,
        Err((400, "unknown request: request-1".to_owned())),
        "the shell cannot submit a shown plan: the caller check runs before the request lookup, so request-1 never reports unknown to a shell"
    );
    assert_eq!(
        record(&stand_in, &first, "request-1"),
        granted,
        "the shell cannot submit a shown plan: the refused shell submit after the spend leaves request-1 granted with the shown hash"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell cannot submit a shown plan: the refused shell submit after the spend leaves the live list empty"
    );
}

#[test]
fn only_a_live_session_submits_a_shown_plan() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shown(stand_in: &StandIn, session: &str) -> Vec<Value> {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
    }

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    fn live(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capability_list(Caller::Shell, Some("all_sessions_live"))
            .expect("shell live list")["capabilities"]
            .as_array()
            .cloned()
            .expect("the shell live list holds a capabilities array")
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

    fn state(stand_in: &StandIn, id: &str) -> Value {
        let listed = capsule(stand_in, id);
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let mut stand_in = StandIn::new();

    // One session that was never launched. The instance lookup runs after the
    // body is accepted, so all three bodies reach it and are refused by name.
    let plans: [&[u8]; 3] = [PLAN_A, PLAN_B, b""];
    for plan in plans {
        let result = request(
            &mut stand_in,
            Caller::Client {
                session_id: "component-absent",
            },
            plan,
            "localhost://Public/plan-approval/a.txt",
            "read",
            "",
        );
        assert_eq!(
            result,
            Err((400, "unknown instance: component-absent".to_owned())),
            "only a live session submits a shown plan: the never-launched session's submit with plan bytes {plan:?} is refused as an unknown instance"
        );
        assert_ne!(
            result,
            Err((
                403,
                "capability request needs an instance session".to_owned()
            )),
            "only a live session submits a shown plan: the client caller reaches the instance lookup, so {plan:?} never reports a caller refusal"
        );
        assert_ne!(
            result,
            Err((
                403,
                "ask not declared in the signed manifest: localhost://Public/plan-approval/a.txt read".to_owned()
            )),
            "only a live session submits a shown plan: the instance lookup runs before the manifest check, so {plan:?} never reaches it"
        );
        assert_ne!(
            result,
            Err((
                400,
                "Invalid action: read. Expected: read, write, execute, delete, message, admin"
                    .to_owned()
            )),
            "only a live session submits a shown plan: the body is accepted before the instance lookup, so {plan:?} never reports an action refusal"
        );
        assert_ne!(
            result,
            Err((
                400,
                "Unsupported resource scheme. Allowed: elastos://, localhost://".to_owned()
            )),
            "only a live session submits a shown plan: the body is accepted before the instance lookup, so {plan:?} never reports a scheme refusal"
        );
        assert_ne!(
            result,
            Err((400, "request body needs resource".to_owned())),
            "only a live session submits a shown plan: the body carries its resource, so {plan:?} never reports a missing resource"
        );
        assert_ne!(
            result,
            Err((400, "instance is not live: stopped".to_owned())),
            "only a live session submits a shown plan: the never-launched session is absent rather than stopped for {plan:?}"
        );
        assert_eq!(
            stand_in
                .get_capsules(Caller::Shell)
                .expect("shell capsules"),
            json!({ "capsules": [] }),
            "only a live session submits a shown plan: the unknown-instance refusal for {plan:?} mints no instance"
        );
        for session in ["component-absent", "component-1", "component-2"] {
            assert_eq!(
                shown(&stand_in, session),
                Vec::<Value>::new(),
                "only a live session submits a shown plan: the unknown-instance refusal for {plan:?} stores no request for {session}"
            );
        }
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "only a live session submits a shown plan: the unknown-instance refusal for {plan:?} mints no grant"
        );
    }

    // Two live sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "only a live session submits a shown plan: the fresh stand-in names its first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "only a live session submits a shown plan: the stand-in names its second session component-2"
    );
    assert_eq!(
        state(&stand_in, &first),
        json!({ "id": "component-1", "status": "running", "cause": "" }),
        "only a live session submits a shown plan: the first session runs with no cause"
    );
    assert_eq!(
        state(&stand_in, &second),
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "only a live session submits a shown plan: the second session runs with no cause"
    );

    // The owner stops the first session. It stays listed as stopped.
    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            &first,
            "stop the shown session"
        ),
        Ok(json!(null)),
        "only a live session submits a shown plan: the owner's stop of component-1 is accepted"
    );
    assert_eq!(
        state(&stand_in, &first),
        json!({
            "id": "component-1",
            "status": "stopped",
            "cause": "stopped: stop the shown session",
        }),
        "only a live session submits a shown plan: the stopped session stays listed as stopped with the stop cause"
    );
    assert_eq!(
        state(&stand_in, &second),
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "only a live session submits a shown plan: the stop leaves the other session running with no cause"
    );
    assert_eq!(
        shown(&stand_in, &first),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the stop leaves component-1's request array empty"
    );
    assert_eq!(
        shown(&stand_in, &second),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the stop leaves component-2's request array empty"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the stop leaves the live list empty"
    );

    // The stopped session's submit is the not-live refusal for all three
    // bodies, because the instance lookup runs after the body is accepted.
    for plan in plans {
        let result = request(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            plan,
            "localhost://Public/plan-approval/a.txt",
            "read",
            "",
        );
        assert_eq!(
            result,
            Err((400, "instance is not live: stopped".to_owned())),
            "only a live session submits a shown plan: the stopped session's submit with plan bytes {plan:?} is refused as not live"
        );
        assert_ne!(
            result,
            Err((400, "unknown instance: component-1".to_owned())),
            "only a live session submits a shown plan: the stopped session is still listed, so {plan:?} is not an unknown instance"
        );
        assert_ne!(
            result,
            Err((
                403,
                "capability request needs an instance session".to_owned()
            )),
            "only a live session submits a shown plan: the client caller reaches the instance lookup, so {plan:?} never reports a caller refusal"
        );
        assert_ne!(
            result,
            Err((400, "instance is not live: failed".to_owned())),
            "only a live session submits a shown plan: the stop is not a worker failure, so {plan:?} never reports a failed instance"
        );
        assert_eq!(
            shown(&stand_in, &first),
            Vec::<Value>::new(),
            "only a live session submits a shown plan: the stopped session's refused submit with plan bytes {plan:?} stores no request"
        );
        assert_eq!(
            shown(&stand_in, &second),
            Vec::<Value>::new(),
            "only a live session submits a shown plan: the stopped session's refused submit with plan bytes {plan:?} leaves component-2's request array empty"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "only a live session submits a shown plan: the stopped session's refused submit with plan bytes {plan:?} mints no grant"
        );
        assert_eq!(
            state(&stand_in, &first),
            json!({
                "id": "component-1",
                "status": "stopped",
                "cause": "stopped: stop the shown session",
            }),
            "only a live session submits a shown plan: the stopped session's refused submit with plan bytes {plan:?} leaves component-1 stopped with the stop cause"
        );
        assert_eq!(
            state(&stand_in, &second),
            json!({ "id": "component-2", "status": "running", "cause": "" }),
            "only a live session submits a shown plan: the stopped session's refused submit with plan bytes {plan:?} leaves component-2 running with no cause"
        );
    }

    // The other running session's submit is the one stored request.
    assert_eq!(
        request(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            PLAN_A,
            "localhost://Public/plan-approval/a.txt",
            "read",
            "",
        ),
        Ok("request-1".to_owned()),
        "only a live session submits a shown plan: the live session's own submit stores the stand-in's first request"
    );

    let shown_hash = plan_sha256(PLAN_A);
    assert_eq!(
        shown_hash.len(),
        64,
        "only a live session submits a shown plan: the shown hash is 64 lowercase hex characters"
    );

    let pending = json!({
        "request_id": "request-1",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": shown_hash,
    });
    assert_eq!(
        record(&stand_in, &second, "request-1"),
        pending,
        "only a live session submits a shown plan: the live session's submit stores one pending request with the shown hash and no decision"
    );
    assert_eq!(
        shown(&stand_in, &first),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the live session's submit stores no request for component-1"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the pending request mints no grant"
    );

    // The shell grants the request the live session submitted.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, "request-1", "once", &shown_hash, "owner approved"),
        Ok(json!({ "success": true })),
        "only a live session submits a shown plan: the owner's approval of request-1 with the shown hash is accepted"
    );

    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": shown_hash,
    });
    assert_eq!(
        record(&stand_in, &second, "request-1"),
        granted,
        "only a live session submits a shown plan: the shell's approval settles request-1 as granted under the shell with the shown hash"
    );

    let live_one = json!({
        "request_id": "request-1",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![live_one.clone()],
        "only a live session submits a shown plan: the shell's approval stores one once grant for request-1"
    );

    // That live session's own use runs once and spends the grant.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            "request-1",
            PLAN_A
        ),
        Ok(json!({ "valid": true })),
        "only a live session submits a shown plan: the live session's own use of request-1 runs"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the spent once grant leaves the live list"
    );

    // The stopped session's submit after that spend is still the not-live
    // refusal, so the instance lookup runs before any request-state check.
    let after_spend = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    );
    assert_eq!(
        after_spend,
        Err((400, "instance is not live: stopped".to_owned())),
        "only a live session submits a shown plan: the stopped session's submit after the spend is still refused as not live"
    );
    assert_ne!(
        after_spend,
        Err((400, "request is not pending: request-1".to_owned())),
        "only a live session submits a shown plan: the instance lookup runs before any request-state check, so the spent request never reports not pending"
    );
    assert_ne!(
        after_spend,
        Err((400, "unknown request: request-1".to_owned())),
        "only a live session submits a shown plan: the submit mints a new request id, so request-1 never reports unknown"
    );
    assert_eq!(
        shown(&stand_in, &first),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the stopped session's refused submit after the spend stores no request"
    );
    assert_eq!(
        record(&stand_in, &second, "request-1"),
        granted,
        "only a live session submits a shown plan: the refused submit after the spend leaves request-1 granted with the shown hash"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "only a live session submits a shown plan: the refused submit after the spend leaves the live list empty"
    );
}

#[cfg(test)]
#[test]
fn agent_cannot_stop_a_shown_session() {
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

    fn shell_refusal() -> Result<Value, (u16, String)> {
        Err((403, "This endpoint requires shell privileges".to_owned()))
    }

    let mut stand_in = StandIn::new();
    let posting_session = Caller::Client {
        session_id: "component-1",
    };

    // A client stop of an absent id and of an empty id is the shell refusal,
    // because the stop route checks the caller before any lookup or body read.
    let absent_stop = stop_shown_session(
        &mut stand_in,
        posting_session,
        "component-absent",
        "stop the shown session",
    );
    assert_eq!(
        absent_stop,
        shell_refusal(),
        "the agent that showed the plan cannot stop its session: a client stop of an absent id is the shell refusal, not an unknown instance"
    );
    assert_ne!(
        absent_stop,
        Err((400, "unknown instance: component-absent".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an absent id runs no instance lookup"
    );
    assert_ne!(
        absent_stop,
        Err((400, "instance is not live: stopped".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an absent id finds no stopped instance"
    );
    assert_ne!(
        absent_stop,
        Err((400, "stop body needs reason".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an absent id reads no stop body"
    );
    let empty_stop =
        stop_shown_session(&mut stand_in, posting_session, "", "stop the shown session");
    assert_eq!(
        empty_stop,
        shell_refusal(),
        "the agent that showed the plan cannot stop its session: a client stop of an empty id is the shell refusal, not a missing stop body"
    );
    assert_ne!(
        empty_stop,
        Err((400, "unknown instance: ".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an empty id runs no instance lookup"
    );
    assert_ne!(
        empty_stop,
        Err((400, "instance is not live: stopped".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an empty id finds no stopped instance"
    );
    assert_ne!(
        empty_stop,
        Err((400, "stop body needs reason".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop of an empty id reads no stop body"
    );
    assert_eq!(
        stand_in.get_capsules(Caller::Shell).expect("shell capsules"),
        json!({ "capsules": [] }),
        "the agent that showed the plan cannot stop its session: the refused client stops mint no instance"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent that showed the plan cannot stop its session: the refused client stops mint no grant"
    );

    // Two sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(first, "component-1", "the first launch is component-1");
    assert_eq!(second, "component-2", "the second launch is component-2");
    for id in [&first, &second] {
        assert_eq!(
            {
                let running = capsule(&stand_in, id);
                json!({ "status": running["status"], "cause": running["cause"] })
            },
            json!({ "status": "running", "cause": "" }),
            "{id} starts running with no cause"
        );
    }

    // The agent that posted the plan asks for it and the owner allows it once.
    let shown_step = request(
        &mut stand_in,
        posting_session,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores the shown plan");
    assert_eq!(
        shown_step, "request-1",
        "the shown plan is the stand-in's first request"
    );
    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(plan_a.len(), 64, "the shown plan hash is SHA-256 hex");
    assert_eq!(plan_b.len(), 64, "the next plan hash is SHA-256 hex");

    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &shown_step,
            "once",
            &plan_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the shown plan once with the hash it saw"
    );

    let one_live = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![one_live.clone()],
        "the owner's approval stores one live grant for the shown step"
    );

    // The session's next step stays pending while the client stops are refused.
    let next_step = request(
        &mut stand_in,
        posting_session,
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores the next pending step");
    assert_eq!(
        next_step, "request-2",
        "the next shown step is the stand-in's second request"
    );

    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    assert_eq!(
        shown(&stand_in, &first),
        vec![granted.clone(), pending.clone()],
        "the shown session holds its granted step and its pending step"
    );

    // Each client stop is refused before the stop body is read and changes
    // nothing: both sessions run, the granted step stays granted, the pending
    // step stays pending, and the live grant stays live.
    let client_stops = [
        (posting_session, "component-1"),
        (
            Caller::Client {
                session_id: "component-2",
            },
            "component-1",
        ),
        (posting_session, "component-2"),
        (posting_session, "component-absent"),
    ];
    for (caller, id) in client_stops {
        let refused = stop_shown_session(&mut stand_in, caller, id, "stop the shown session");
        assert_eq!(
            refused,
            shell_refusal(),
            "the agent that showed the plan cannot stop its session: the client stop of {id} is the shell refusal"
        );
        assert_ne!(
            refused,
            Err((400, "unknown instance: component-absent".to_owned())),
            "the agent that showed the plan cannot stop its session: the client stop of {id} runs no instance lookup"
        );
        assert_ne!(
            refused,
            Err((400, "instance is not live: stopped".to_owned())),
            "the agent that showed the plan cannot stop its session: the client stop of {id} finds no stopped instance"
        );
        assert_ne!(
            refused,
            Err((400, "stop body needs reason".to_owned())),
            "the agent that showed the plan cannot stop its session: the client stop of {id} reads no stop body"
        );
        assert_ne!(
            refused,
            Err((400, "stop body misses reason".to_owned())),
            "the agent that showed the plan cannot stop its session: the client stop of {id} reads no stop body"
        );
        for running in [&first, &second] {
            assert_eq!(
                {
                    let held = capsule(&stand_in, running);
                    json!({ "status": held["status"], "cause": held["cause"] })
                },
                json!({ "status": "running", "cause": "" }),
                "the agent that showed the plan cannot stop its session: {running} stays running with no cause after the client stop of {id}"
            );
        }
        assert_eq!(
            shown(&stand_in, &first),
            vec![granted.clone(), pending.clone()],
            "the agent that showed the plan cannot stop its session: the refused client stop of {id} leaves the granted step granted and the pending step pending"
        );
        assert_eq!(
            live(&stand_in),
            vec![one_live.clone()],
            "the agent that showed the plan cannot stop its session: the refused client stop of {id} leaves the live grant live"
        );
    }

    // The shell's own stop settles that session.
    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            &first,
            "stop the shown session"
        ),
        Ok(Value::Null),
        "the shell stop of the shown session reports its settlement"
    );
    assert_eq!(
        {
            let stopped = capsule(&stand_in, &first);
            json!({ "status": stopped["status"], "cause": stopped["cause"] })
        },
        json!({ "status": "stopped", "cause": "stopped: stop the shown session" }),
        "the shell stop stores the shown session as stopped with the stop cause"
    );
    assert_eq!(
        {
            let other = capsule(&stand_in, &second);
            json!({ "status": other["status"], "cause": other["cause"] })
        },
        json!({ "status": "running", "cause": "" }),
        "the shell stop leaves the other session running"
    );

    let settled = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "denied",
        "decision_reason": "stopped: stop the shown session",
        "settled_by": "runtime",
        "plan": plan_b,
    });
    assert_eq!(
        shown(&stand_in, &first),
        vec![granted.clone(), settled.clone()],
        "the shell stop denies that session's pending step with the runtime settler and keeps its plan hash"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the shell stop revokes that session's live grant"
    );

    // The revoked grant is refused through the existing use path.
    assert_eq!(
        execute(&mut stand_in, posting_session, &shown_step, PLAN_A),
        Err((400, "grant is not live: Revoked".to_owned())),
        "the shell stop's revoked grant refuses its own plan's use"
    );

    // A client stop of the stopped session is still the shell refusal.
    let after_stop = stop_shown_session(
        &mut stand_in,
        posting_session,
        &first,
        "stop the shown session",
    );
    assert_eq!(
        after_stop,
        shell_refusal(),
        "the agent that showed the plan cannot stop its session: a client stop after the settlement is the shell refusal"
    );
    assert_ne!(
        after_stop,
        Err((400, "instance is not live: stopped".to_owned())),
        "the agent that showed the plan cannot stop its session: a client stop after the settlement never reaches the instance state"
    );
    assert_eq!(
        {
            let stopped = capsule(&stand_in, &first);
            json!({ "status": stopped["status"], "cause": stopped["cause"] })
        },
        json!({ "status": "stopped", "cause": "stopped: stop the shown session" }),
        "the refused client stop leaves the shown session stopped with the stop cause"
    );
    assert_eq!(
        shown(&stand_in, &first),
        vec![granted.clone(), settled.clone()],
        "the refused client stop leaves the denied step denied by the runtime"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the refused client stop leaves the live list empty"
    );

    // The other session can still submit, be granted and spend one use.
    let other_session = Caller::Client {
        session_id: "component-2",
    };
    let other_step = request(
        &mut stand_in,
        other_session,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the other session's request route stores its plan");
    assert_eq!(
        other_step, "request-3",
        "the other session's plan is the stand-in's third request"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            &other_step,
            "once",
            &plan_a,
            "owner approved"
        ),
        Ok(json!({ "success": true })),
        "the owner allows the other session's plan once with the hash it saw"
    );
    let other_live = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![other_live.clone()],
        "the other session's approval stores one live grant"
    );
    assert_eq!(
        execute(&mut stand_in, other_session, &other_step, PLAN_A),
        Ok(json!({ "valid": true })),
        "the other session's allow-once grant authorises its own use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the other session's once grant is spent by its one use"
    );
}

#[cfg(test)]
#[test]
fn agent_cannot_launch_a_shown_session() {
    use agent_conformance::standin_runtime::Caller;
    use fixtures::PLAN_A;
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
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

    fn capsule_ids(stand_in: &StandIn) -> Vec<String> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .expect("the capsule list holds a capsules array")
            .iter()
            .map(|entry| {
                entry["id"]
                    .as_str()
                    .expect("a capsule entry names its id")
                    .to_owned()
            })
            .collect()
    }

    fn shell_refusal() -> Result<String, (u16, String)> {
        Err((403, "This endpoint requires shell privileges".to_owned()))
    }

    fn refusal_reason(refused: &Result<String, (u16, String)>) -> &str {
        refused
            .as_ref()
            .err()
            .map(|(_, reason)| reason.as_str())
            .expect("a client launch is refused")
    }

    let mut stand_in = StandIn::new();

    // A client launch never reaches the list body or an admission: the list
    // route's shell check runs first, so a session id that was never launched,
    // an absent id and an empty id are the same refusal and store nothing.
    let fresh_launches = [
        (
            Caller::Client {
                session_id: "component-1",
            },
            "component-1",
        ),
        (
            Caller::Client {
                session_id: "component-absent",
            },
            "component-absent",
        ),
        (Caller::Client { session_id: "" }, "an empty id"),
    ];
    for (caller, label) in fresh_launches {
        let refused = running_agent(&mut stand_in, caller);
        assert_eq!(
            refused,
            shell_refusal(),
            "the agent cannot launch a shown session: a client launch for {label} on a fresh stand-in is the shell refusal"
        );
        assert_ne!(
            refused,
            Err((400, "unknown instance: component-absent".to_owned())),
            "the agent cannot launch a shown session: the client launch for {label} runs no instance lookup"
        );
        assert_ne!(
            refused,
            Err((400, "unknown instance: component-1".to_owned())),
            "the agent cannot launch a shown session: the client launch for {label} runs no instance lookup"
        );
        assert_ne!(
            refused,
            Err((400, "unknown instance: ".to_owned())),
            "the agent cannot launch a shown session: the client launch for {label} runs no instance lookup"
        );
        assert_ne!(
            refusal_reason(&refused),
            "resident launch body needs cid",
            "the agent cannot launch a shown session: the client launch for {label} reads no launch body"
        );
        assert!(
            !refusal_reason(&refused).starts_with("bundle already admitted"),
            "the agent cannot launch a shown session: the client launch for {label} admits no bundle"
        );
        assert!(
            !refusal_reason(&refused).starts_with("no bundle is admitted"),
            "the agent cannot launch a shown session: the client launch for {label} launches no admitted bundle"
        );
        assert_eq!(
            stand_in
                .get_capsules(Caller::Shell)
                .expect("shell capsules"),
            json!({ "capsules": [] }),
            "the agent cannot launch a shown session: the refused client launch for {label} stores no instance"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the agent cannot launch a shown session: the refused client launch for {label} mints no grant"
        );
        assert_eq!(
            shown(&stand_in, "component-1"),
            Vec::<Value>::new(),
            "the agent cannot launch a shown session: the refused client launch for {label} stores no request for component-1"
        );
        assert_eq!(
            shown(&stand_in, "component-absent"),
            Vec::<Value>::new(),
            "the agent cannot launch a shown session: the refused client launch for {label} stores no request for component-absent"
        );
    }

    // The shell's own launch is the existing journey and starts component-1.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "the agent cannot launch a shown session: the shell's first launch is component-1"
    );
    assert_eq!(
        {
            let running = capsule(&stand_in, &first);
            json!({ "status": running["status"], "cause": running["cause"] })
        },
        json!({ "status": "running", "cause": "" }),
        "the agent cannot launch a shown session: the shell's launch starts component-1 running with no cause"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the shell's launch mints no grant"
    );
    assert_eq!(
        shown(&stand_in, &first),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the shell's launch stores no request"
    );

    // A client launch after the shell has launched is still the shell refusal:
    // it mints no component-3 and leaves component-1 running.
    let launched_launches = [
        (
            Caller::Client {
                session_id: "component-1",
            },
            "component-1",
        ),
        (
            Caller::Client {
                session_id: "component-2",
            },
            "component-2",
        ),
        (Caller::Client { session_id: "" }, "an empty id"),
    ];
    for (caller, label) in launched_launches {
        let refused = running_agent(&mut stand_in, caller);
        assert_eq!(
            refused,
            shell_refusal(),
            "the agent cannot launch a shown session: a client launch for {label} after the shell's launch is the shell refusal"
        );
        assert!(
            !refusal_reason(&refused).starts_with("bundle already admitted"),
            "the agent cannot launch a shown session: the client launch for {label} finds no already-admitted bundle"
        );
        assert_ne!(
            refusal_reason(&refused),
            "unknown instance: component-2",
            "the agent cannot launch a shown session: the client launch for {label} runs no instance lookup"
        );
        assert_ne!(
            refusal_reason(&refused),
            "instance is not live: stopped",
            "the agent cannot launch a shown session: the client launch for {label} reaches no instance state"
        );
        assert_eq!(
            {
                let running = capsule(&stand_in, &first);
                json!({ "status": running["status"], "cause": running["cause"] })
            },
            json!({ "status": "running", "cause": "" }),
            "the agent cannot launch a shown session: component-1 stays running with no cause after the client launch for {label}"
        );
        assert_eq!(
            capsule_ids(&stand_in),
            vec!["component-1".to_owned()],
            "the agent cannot launch a shown session: the capsule list holds one entry, component-1, after the client launch for {label}"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "the agent cannot launch a shown session: the refused client launch for {label} mints no grant"
        );
    }

    // The shell's second launch is component-2, and component-1 stays running.
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "the agent cannot launch a shown session: the shell's second launch is component-2"
    );
    for id in [&first, &second] {
        assert_eq!(
            {
                let running = capsule(&stand_in, id);
                json!({ "status": running["status"], "cause": running["cause"] })
            },
            json!({ "status": "running", "cause": "" }),
            "the agent cannot launch a shown session: {id} runs with no cause"
        );
    }

    // The shown session submits its plan and the owner allows it once.
    let client_session = Caller::Client {
        session_id: "component-1",
    };
    let shown_step = request(
        &mut stand_in,
        client_session,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's request route stores the shown plan");
    assert_eq!(
        shown_step, "request-1",
        "the agent cannot launch a shown session: the shown plan is the stand-in's first request"
    );
    let plan_a = plan_sha256(PLAN_A);
    assert_eq!(
        plan_a.len(),
        64,
        "the agent cannot launch a shown session: the shown plan hash is SHA-256 hex"
    );
    let pending = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &shown_step),
        pending,
        "the agent cannot launch a shown session: the shown step is pending with the plan hash the owner will see"
    );
    assert_eq!(
        shown(&stand_in, &second),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the other session stores no request"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the pending step mints no grant"
    );

    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &shown_step, "once", &plan_a, "owner approved"),
        Ok(json!({ "success": true })),
        "the agent cannot launch a shown session: the owner allows the shown plan once with the hash it saw"
    );
    let granted = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &shown_step),
        granted,
        "the agent cannot launch a shown session: the owner's approval stores the shown step as granted by the shell"
    );
    let one_live = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    assert_eq!(
        live(&stand_in),
        vec![one_live.clone()],
        "the agent cannot launch a shown session: the owner's approval stores one live grant for the shown step"
    );

    assert_eq!(
        execute(&mut stand_in, client_session, &shown_step, PLAN_A),
        Ok(json!({ "valid": true })),
        "the agent cannot launch a shown session: the shown session's allow-once grant authorises its own use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the shown session's once grant is spent by its one use"
    );

    // A client launch after both shell sessions is still the shell refusal and
    // mints no component-3; the granted step stays granted.
    let after_two = running_agent(&mut stand_in, client_session);
    assert_eq!(
        after_two,
        shell_refusal(),
        "the agent cannot launch a shown session: a client launch after both shell sessions is the shell refusal"
    );
    assert!(
        !refusal_reason(&after_two).starts_with("bundle already admitted"),
        "the agent cannot launch a shown session: the client launch after both shell sessions finds no already-admitted bundle"
    );
    assert_eq!(
        capsule_ids(&stand_in),
        vec!["component-1".to_owned(), "component-2".to_owned()],
        "the agent cannot launch a shown session: the capsule list holds component-1 and component-2 and no component-3"
    );
    for id in [&first, &second] {
        assert_eq!(
            {
                let running = capsule(&stand_in, id);
                json!({ "status": running["status"], "cause": running["cause"] })
            },
            json!({ "status": "running", "cause": "" }),
            "the agent cannot launch a shown session: {id} stays running with no cause after the refused client launch"
        );
    }
    assert_eq!(
        record(&stand_in, &first, &shown_step),
        granted,
        "the agent cannot launch a shown session: the refused client launch leaves the shown step granted by the shell"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the refused client launch leaves the live list empty"
    );

    // The other shell session can also submit, be granted and spend one use.
    let other_session = Caller::Client {
        session_id: "component-2",
    };
    let other_step = request(
        &mut stand_in,
        other_session,
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the other session's request route stores its plan");
    assert_eq!(
        other_step, "request-2",
        "the agent cannot launch a shown session: the other session's plan is the stand-in's second request"
    );
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &other_step, "once", &plan_a, "owner approved"),
        Ok(json!({ "success": true })),
        "the agent cannot launch a shown session: the owner allows the other session's plan once with the hash it saw"
    );
    assert_eq!(
        execute(&mut stand_in, other_session, &other_step, PLAN_A),
        Ok(json!({ "valid": true })),
        "the agent cannot launch a shown session: the other shell session's allow-once grant authorises its own use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "the agent cannot launch a shown session: the other shell session's once grant is spent by its one use"
    );
}

#[cfg(test)]
#[test]
fn shown_request_status_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
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

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        shown(stand_in, session)
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let absent_error: Result<Value, (u16, String)> =
        Err((404, "Request not found: request-absent".to_owned()));
    let forbidden: Result<Value, (u16, String)> =
        Err((403, "Cannot access another session's request".to_owned()));
    let shell_refusal: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));
    let unknown_request: Result<Value, (u16, String)> =
        Err((400, "unknown request: request-absent".to_owned()));

    let mut stand_in = StandIn::new();

    // The lookup runs before the caller check, so a missing id is the not-found
    // answer for every caller, the shell included.
    for session_id in ["component-1", "component-2", ""] {
        let read = read_shown_request(&stand_in, Caller::Client { session_id }, "request-absent");
        assert_eq!(
            read, absent_error,
            "a shown request status is not the grant: the status read of an absent id is not found for the session {session_id}"
        );
        assert_ne!(
            read, forbidden,
            "a shown request status is not the grant: an absent id is not another session's request for {session_id}"
        );
        assert_ne!(
            read, shell_refusal,
            "a shown request status is not the grant: the status read is not a shell-only route for {session_id}"
        );
        assert_ne!(
            read, unknown_request,
            "a shown request status is not the grant: an absent id is not an unknown request for {session_id}"
        );
        assert_eq!(
            stand_in
                .get_capsules(Caller::Shell)
                .expect("shell capsules"),
            json!({ "capsules": [] }),
            "a shown request status is not the grant: the absent-id read as {session_id} stores no instance"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "a shown request status is not the grant: the absent-id read as {session_id} mints no grant"
        );
    }

    let shell_read = read_shown_request(&stand_in, Caller::Shell, "request-absent");
    assert_eq!(
        shell_read, absent_error,
        "a shown request status is not the grant: the shell's status read of an absent id is not found"
    );
    assert_ne!(
        shell_read, forbidden,
        "a shown request status is not the grant: the shell's absent-id read is not another session's request"
    );
    assert_ne!(
        shell_read, shell_refusal,
        "a shown request status is not the grant: the shell may read a status"
    );
    assert_ne!(
        shell_read, unknown_request,
        "a shown request status is not the grant: the shell's absent-id read is not an unknown request"
    );
    assert_eq!(
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules"),
        json!({ "capsules": [] }),
        "a shown request status is not the grant: the shell's absent-id read stores no instance"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown request status is not the grant: the shell's absent-id read mints no grant"
    );

    // Two running sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown request status is not the grant: the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "a shown request status is not the grant: the second running session is the stand-in's next component"
    );
    let capsules = stand_in
        .get_capsules(Caller::Shell)
        .expect("shell capsules");
    let listed = capsules["capsules"]
        .as_array()
        .cloned()
        .expect("the shell capsule list holds a capsules array");
    assert_eq!(
        listed.len(),
        2,
        "a shown request status is not the grant: both shell launches stay on the capsule list"
    );
    for capsule in &listed {
        assert_eq!(
            json!({
                "id": capsule["id"],
                "status": capsule["status"],
                "cause": capsule["cause"],
            }),
            json!({
                "id": capsule["id"],
                "status": "running",
                "cause": "",
            }),
            "a shown request status is not the grant: each launched session is running with no cause"
        );
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_a.len(),
        64,
        "a shown request status is not the grant: the shown hash of plan A is 64 characters"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown request status is not the grant: the shown hash of plan B is 64 characters"
    );

    let first_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the first shown plan");
    assert_eq!(
        first_step, "request-1",
        "a shown request status is not the grant: the first session's shown plan is the stand-in's first request"
    );

    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &first_step),
        pending_a,
        "a shown request status is not the grant: the shell's own request view shows the pending step with its hash"
    );

    // The owning session reads only the status word.
    let owner_pending = read_shown_request(
        &stand_in,
        Caller::Client { session_id: &first },
        &first_step,
    );
    assert_eq!(
        owner_pending,
        Ok(json!({ "status": "pending" })),
        "a shown request status is not the grant: the owning session's status read is the stored status word"
    );
    let value = owner_pending
        .as_ref()
        .expect("the owning session reads the status");
    for key in ["plan", "resource", "request_id", "token"] {
        assert!(
            value.get(key).is_none(),
            "a shown request status is not the grant: the status body carries no {key}"
        );
    }
    assert_eq!(
        record(&stand_in, &first, &first_step),
        pending_a,
        "a shown request status is not the grant: the status read leaves the pending row as it was"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown request status is not the grant: the status read mints no grant"
    );

    // Another session, an empty session id and the shell own no shown request.
    for caller in [
        Caller::Client {
            session_id: "component-2",
        },
        Caller::Client { session_id: "" },
        Caller::Shell,
    ] {
        let read = read_shown_request(&stand_in, caller, &first_step);
        assert_eq!(
            read, forbidden,
            "a shown request status is not the grant: only the owning session reads this status, {caller:?} is refused"
        );
        assert_ne!(
            read,
            Ok(json!({ "status": "pending" })),
            "a shown request status is not the grant: {caller:?} does not receive the status word"
        );
        assert_ne!(
            read,
            Err((404, "Request not found: request-1".to_owned())),
            "a shown request status is not the grant: the id exists for {caller:?}"
        );
        assert_ne!(
            read, shell_refusal,
            "a shown request status is not the grant: the status read is not a shell-only route for {caller:?}"
        );
        assert_eq!(
            record(&stand_in, &first, &first_step),
            pending_a,
            "a shown request status is not the grant: the refused read by {caller:?} leaves the pending row"
        );
        assert_eq!(
            live(&stand_in),
            Vec::<Value>::new(),
            "a shown request status is not the grant: the refused read by {caller:?} mints no grant"
        );
    }

    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &first },
            "request-absent",
        ),
        absent_error,
        "a shown request status is not the grant: the owning session's read of an absent id is not found, not another session's request"
    );

    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &second,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the other session's submit stores the second shown plan");
    assert_eq!(
        second_step, "request-2",
        "a shown request status is not the grant: the other session's shown plan is the stand-in's second request"
    );

    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &first },
            &second_step,
        ),
        forbidden,
        "a shown request status is not the grant: the first session does not read the other session's status"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: &second
            },
            &second_step,
        ),
        Ok(json!({ "status": "pending" })),
        "a shown request status is not the grant: the other session reads its own pending status"
    );

    // The shell's deny settles the record. The owner's later read shows the
    // decision reason and still no plan.
    assert_eq!(
        deny_shown_plan(
            &mut stand_in,
            Caller::Shell,
            &first_step,
            "deny the shown plan"
        ),
        Ok(json!({ "success": true })),
        "a shown request status is not the grant: the shell denies the one shown step"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &first },
            &first_step,
        ),
        Ok(json!({ "status": "denied", "reason": "deny the shown plan" })),
        "a shown request status is not the grant: the owning session's denied status carries the decision reason"
    );
    let denied_body = read_shown_request(
        &stand_in,
        Caller::Client { session_id: &first },
        &first_step,
    )
    .expect("the owning session reads the denied status");
    for key in ["plan", "decision_reason"] {
        assert!(
            denied_body.get(key).is_none(),
            "a shown request status is not the grant: the denied status body carries no {key}"
        );
    }
    let denied_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "denied",
        "decision_reason": "deny the shown plan",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &first, &first_step),
        denied_a,
        "a shown request status is not the grant: the shell's view keeps the denied row and its hash"
    );
    assert_eq!(
        record(&stand_in, &second, &second_step),
        pending_b,
        "a shown request status is not the grant: the shell's deny leaves the other session's plan pending"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown request status is not the grant: a denied step is not a live grant"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &second },
            &first_step,
        ),
        forbidden,
        "a shown request status is not the grant: the other session reads a refusal, not the denied body"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &second },
            &first_step,
        ),
        Ok(json!({ "status": "denied", "reason": "deny the shown plan" })),
        "a shown request status is not the grant: the denied body belongs to the owning session alone"
    );

    // The owner's grant is the only thing a status read is not.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &second_step, "once", &plan_b, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown request status is not the grant: the owner allows the pending step once with the hash it saw"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: &second
            },
            &second_step,
        ),
        Ok(json!({ "status": "granted" })),
        "a shown request status is not the grant: the owning session reads the granted status word"
    );
    let granted_body = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: &second,
        },
        &second_step,
    )
    .expect("the owning session reads the granted status");
    for key in ["plan", "reason"] {
        assert!(
            granted_body.get(key).is_none(),
            "a shown request status is not the grant: the granted status body carries no {key}"
        );
    }
    let allowed = vec![json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    })];
    assert_eq!(
        live(&stand_in),
        allowed,
        "a shown request status is not the grant: the owner's approve mints the one live grant"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second
            },
            &second_step,
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown request status is not the grant: the live once grant authorises its one use"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown request status is not the grant: the once grant is spent"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: &second
            },
            &second_step,
        ),
        Ok(json!({ "status": "granted" })),
        "a shown request status is not the grant: a spent once grant still reads granted"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &second },
            &second_step,
            PLAN_B,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown request status is not the grant: the status word is not the live grant, so the next use is refused"
    );

    let third_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's later submit stores the third shown plan");
    assert_eq!(
        third_step, "request-3",
        "a shown request status is not the grant: the later shown plan is the stand-in's third request"
    );

    age_shown_plan(&mut stand_in, 300);

    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &first },
            &third_step,
        ),
        Ok(json!({ "status": "expired", "reason": "Request timed out" })),
        "a shown request status is not the grant: the owning session's expired status carries the decision reason"
    );
    let expired_body = read_shown_request(
        &stand_in,
        Caller::Client { session_id: &first },
        &third_step,
    )
    .expect("the owning session reads the expired status");
    assert!(
        expired_body.get("plan").is_none(),
        "a shown request status is not the grant: the expired status body carries no plan"
    );

    let expired_a = json!({
        "request_id": "request-3",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "expired",
        "decision_reason": "Request timed out",
        "settled_by": "runtime",
        "plan": plan_a,
    });
    let granted_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &first, &third_step),
        expired_a,
        "a shown request status is not the grant: the shell's view keeps the expired row and its hash"
    );
    assert_eq!(
        record(&stand_in, &first, &first_step),
        denied_a,
        "a shown request status is not the grant: the denied row keeps its shell settlement"
    );
    assert_eq!(
        record(&stand_in, &second, &second_step),
        granted_b,
        "a shown request status is not the grant: the granted row keeps its owner settlement"
    );
    assert_eq!(
        live(&stand_in),
        Vec::<Value>::new(),
        "a shown request status is not the grant: the reads and the expiry mint no grant"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client { session_id: &first },
            &first_step,
        ),
        Ok(json!({ "status": "denied", "reason": "deny the shown plan" })),
        "a shown request status is not the grant: the earlier denied status still reads its decision reason"
    );
}

#[cfg(test)]
#[test]
fn shown_live_list_is_not_another_sessions_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_live(stand_in: &StandIn, scope: Option<&str>) -> Value {
        read_shown_grants(stand_in, Caller::Shell, scope).expect("the shell reads the live list")
    }

    fn client_live(stand_in: &StandIn, session_id: &str) -> Value {
        read_shown_grants(stand_in, Caller::Client { session_id }, None)
            .expect("the client reads its own live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    fn capsule(stand_in: &StandIn, id: &str) -> Value {
        shell_capsules(stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id)
            .expect("the shell capsule list holds that id")
    }

    fn record(stand_in: &StandIn, session: &str, request_id: &str) -> Value {
        stand_in
            .get_capability_requests(Caller::Shell, Some(session))
            .expect("the shell reads the session's requests")["requests"]
            .as_array()
            .cloned()
            .expect("the shell request view holds a requests array")
            .into_iter()
            .find(|entry| entry["request_id"] == request_id)
            .expect("the session's request view holds that id")
    }

    let empty_client: Value = json!({ "capabilities": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let unknown_session: Result<Value, (u16, String)> =
        Err((400, "unknown capability list scope: session".to_owned()));
    let unknown_empty: Result<Value, (u16, String)> =
        Err((400, "unknown capability list scope: ".to_owned()));
    let shell_only: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));

    let mut stand_in = StandIn::new();

    // On a fresh stand-in the client list is empty for every session id and for
    // the shell. Neither list mints anything.
    for session_id in ["component-1", "component-2", "component-absent", ""] {
        let read = read_shown_grants(&stand_in, Caller::Client { session_id }, None);
        assert_eq!(
            read,
            Ok(empty_client.clone()),
            "a shown live list is not another session's grant: the no-scope read for {session_id} on a fresh stand-in is the empty client list"
        );
        let value = read
            .as_ref()
            .expect("the client reads its own live list on a fresh stand-in");
        assert!(
            value.get("scope").is_none(),
            "a shown live list is not another session's grant: the no-scope body for {session_id} carries no scope"
        );
        assert_ne!(
            value, &empty_shell,
            "a shown live list is not another session's grant: the no-scope body for {session_id} is not the shell body"
        );
        assert_eq!(
            shell_live(&stand_in, None),
            empty_shell,
            "a shown live list is not another session's grant: the read by {session_id} leaves the shell live list empty"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown live list is not another session's grant: the read by {session_id} leaves the capsule list empty"
        );
    }

    // The shell's no-scope read is the shell body with the live scope, and its
    // explicit live-scope read is the same value.
    let shell_plain = read_shown_grants(&stand_in, Caller::Shell, None);
    assert_eq!(
        shell_plain,
        Ok(empty_shell.clone()),
        "a shown live list is not another session's grant: the shell's no-scope read on a fresh stand-in is the empty shell body"
    );
    assert_eq!(
        shell_plain,
        read_shown_grants(&stand_in, Caller::Shell, Some("all_sessions_live")),
        "a shown live list is not another session's grant: the shell's no-scope read and its live-scope read are the same body"
    );

    // A scope other than the live scope is the route's scope refusal, for the
    // shell and for a client alike, because the scope check runs first.
    for caller in [
        Caller::Client {
            session_id: "component-1",
        },
        Caller::Client { session_id: "" },
        Caller::Shell,
    ] {
        let read = read_shown_grants(&stand_in, caller, Some("session"));
        assert_eq!(
            read, unknown_session,
            "a shown live list is not another session's grant: the scope session is unknown for {caller:?}"
        );
        assert_ne!(
            read, shell_only,
            "a shown live list is not another session's grant: the unknown scope is not the shell refusal for {caller:?}"
        );
        assert!(
            read.is_err(),
            "a shown live list is not another session's grant: the unknown scope returns no body for {caller:?}"
        );
        assert_eq!(
            shell_live(&stand_in, None),
            empty_shell,
            "a shown live list is not another session's grant: the unknown-scope read by {caller:?} leaves the shell live list empty"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown live list is not another session's grant: the unknown-scope read by {caller:?} leaves the capsule list empty"
        );
    }
    for caller in [
        Caller::Client {
            session_id: "component-1",
        },
        Caller::Shell,
    ] {
        let read = read_shown_grants(&stand_in, caller, Some(""));
        assert_eq!(
            read, unknown_empty,
            "a shown live list is not another session's grant: the empty scope is unknown for {caller:?}"
        );
        assert_ne!(
            read, shell_only,
            "a shown live list is not another session's grant: the empty scope is not the shell refusal for {caller:?}"
        );
        assert!(
            read.is_err(),
            "a shown live list is not another session's grant: the empty scope returns no body for {caller:?}"
        );
        assert_eq!(
            shell_live(&stand_in, None),
            empty_shell,
            "a shown live list is not another session's grant: the empty-scope read by {caller:?} leaves the shell live list empty"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown live list is not another session's grant: the empty-scope read by {caller:?} leaves the capsule list empty"
        );
    }

    // A client ask for every session is the shell refusal, and it returns no
    // body of another session's grants.
    for session_id in ["component-1", "component-absent", ""] {
        let read = read_shown_grants(
            &stand_in,
            Caller::Client { session_id },
            Some("all_sessions_live"),
        );
        assert_eq!(
            read, shell_only,
            "a shown live list is not another session's grant: a client ask for every session is the shell refusal for {session_id}"
        );
        assert_ne!(
            read,
            Err((
                400,
                "unknown capability list scope: all_sessions_live".to_owned()
            )),
            "a shown live list is not another session's grant: the live scope is a known scope for {session_id}"
        );
        assert!(
            !matches!(&read, Ok(value) if value.to_string().contains("request-1")),
            "a shown live list is not another session's grant: the refused client ask for every session returns no body that names request-1 for {session_id}"
        );
        assert_eq!(
            shell_live(&stand_in, None),
            empty_shell,
            "a shown live list is not another session's grant: the refused ask by {session_id} leaves the shell live list empty"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown live list is not another session's grant: the refused ask by {session_id} leaves the capsule list empty"
        );
    }

    // Two running sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown live list is not another session's grant: the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "a shown live list is not another session's grant: the second running session is the stand-in's next component"
    );
    let listed = shell_capsules(&stand_in);
    assert_eq!(
        listed.len(),
        2,
        "a shown live list is not another session's grant: both shell launches stay on the capsule list"
    );
    for entry in &listed {
        assert_eq!(
            json!({
                "id": entry["id"],
                "status": entry["status"],
                "cause": entry["cause"],
            }),
            json!({
                "id": entry["id"],
                "status": "running",
                "cause": "",
            }),
            "a shown live list is not another session's grant: each launched session is running with no cause"
        );
    }

    // The launch mints no grant, so the client list and the shell list stay
    // empty and the client ask for every session stays refused.
    assert_eq!(
        read_shown_grants(&stand_in, Caller::Client { session_id: &first }, None),
        Ok(empty_client.clone()),
        "a shown live list is not another session's grant: the first session's no-scope live list stays empty after its launch"
    );
    assert_eq!(
        read_shown_grants(
            &stand_in,
            Caller::Client { session_id: &first },
            Some("all_sessions_live"),
        ),
        shell_only,
        "a shown live list is not another session's grant: the first session's ask for every session stays the shell refusal after its launch"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        empty_shell,
        "a shown live list is not another session's grant: the launch mints no live grant"
    );

    let plan_a = plan_sha256(PLAN_A);
    assert_eq!(
        plan_a.len(),
        64,
        "a shown live list is not another session's grant: the shown hash of plan A is 64 characters"
    );
    let first_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the first shown plan");
    assert_eq!(
        first_step, "request-1",
        "a shown live list is not another session's grant: the first session's shown plan is the stand-in's first request"
    );
    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &first_step),
        pending_a,
        "a shown live list is not another session's grant: the shell request view shows the pending step with its hash"
    );
    assert_eq!(
        client_live(&stand_in, &first),
        empty_client,
        "a shown live list is not another session's grant: the pending request is not in the first session's live list"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        empty_shell,
        "a shown live list is not another session's grant: the pending request is not in the shell live list"
    );

    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_b.len(),
        64,
        "a shown live list is not another session's grant: the shown hash of plan B is 64 characters"
    );
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &second,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the other session's submit stores the second shown plan");
    assert_eq!(
        second_step, "request-2",
        "a shown live list is not another session's grant: the other session's shown plan is the stand-in's second request"
    );
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &second, &second_step),
        pending_b,
        "a shown live list is not another session's grant: the shell request view shows the other pending step with its hash"
    );
    assert_eq!(
        client_live(&stand_in, &first),
        empty_client,
        "a shown live list is not another session's grant: the other session's pending request is not in the first session's live list"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        empty_shell,
        "a shown live list is not another session's grant: both pending requests stay out of the shell live list"
    );

    // The owner's grant is the only thing these lists ever show.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &first_step, "once", &plan_a, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown live list is not another session's grant: the owner allows the first pending step once with the hash it saw"
    );
    let one_grant = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let shell_one = json!({ "scope": "all_sessions_live", "capabilities": [one_grant.clone()] });
    let read_shell = shell_live(&stand_in, None);
    assert_eq!(
        read_shell, shell_one,
        "a shown live list is not another session's grant: the shell's no-scope read shows the one live grant"
    );
    assert_eq!(
        shell_live(&stand_in, Some("all_sessions_live")),
        shell_one,
        "a shown live list is not another session's grant: the shell's live-scope read is the same body"
    );
    for entry in read_shell["capabilities"]
        .as_array()
        .expect("the shell live list holds a capabilities array")
    {
        for key in ["plan", "token"] {
            assert!(
                entry.get(key).is_none(),
                "a shown live list is not another session's grant: the shell live entry carries no {key}"
            );
        }
    }

    let one_client = json!({
        "capabilities": [{
            "request_id": "request-1",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "once",
            "granted_at": 0,
        }]
    });
    let read_first = client_live(&stand_in, &first);
    assert_eq!(
        read_first, one_client,
        "a shown live list is not another session's grant: the first session's no-scope list holds only its own live grant"
    );
    assert!(
        read_first.get("scope").is_none(),
        "a shown live list is not another session's grant: the client list carries no scope"
    );
    for entry in read_first["capabilities"]
        .as_array()
        .expect("the client live list holds a capabilities array")
    {
        for key in ["session_id", "plan", "token"] {
            assert!(
                entry.get(key).is_none(),
                "a shown live list is not another session's grant: the client live entry carries no {key}"
            );
        }
    }

    // Every other client sees no grant at all, and no client may ask for the
    // whole list.
    for session_id in [second.as_str(), "", "component-absent"] {
        assert_eq!(
            client_live(&stand_in, session_id),
            empty_client,
            "a shown live list is not another session's grant: the first session's grant is not in the live list for {session_id}"
        );
    }
    for session_id in [second.as_str(), first.as_str()] {
        let read = read_shown_grants(
            &stand_in,
            Caller::Client { session_id },
            Some("all_sessions_live"),
        );
        assert_eq!(
            read, shell_only,
            "a shown live list is not another session's grant: a client ask for every session is the shell refusal for {session_id}"
        );
        assert!(
            !matches!(&read, Ok(value) if value.to_string().contains("request-1")),
            "a shown live list is not another session's grant: the refusal returns no body that names request-1 for {session_id}"
        );
    }

    // A read leaves the list as it was.
    assert_eq!(
        client_live(&stand_in, &first),
        one_client,
        "a shown live list is not another session's grant: a second client read is still that one entry"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        shell_one,
        "a shown live list is not another session's grant: the shell live list is still that one entry"
    );
    let granted_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    assert_eq!(
        record(&stand_in, &first, &first_step),
        granted_a,
        "a shown live list is not another session's grant: the shell request view shows the owner's settlement"
    );

    // A session grant lasts until that session stops.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &second_step, "session", &plan_b, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown live list is not another session's grant: the owner allows the second pending step for that session"
    );
    let both = json!({
        "scope": "all_sessions_live",
        "capabilities": [
            one_grant,
            {
                "request_id": "request-2",
                "session_id": "component-2",
                "resource": "localhost://Public/plan-approval/a.txt",
                "action": "read",
                "duration": "session",
                "granted_at": 0,
            },
        ],
    });
    assert_eq!(
        shell_live(&stand_in, None),
        both,
        "a shown live list is not another session's grant: the shell's no-scope read shows both live grants"
    );
    assert_eq!(
        shell_live(&stand_in, Some("all_sessions_live")),
        both,
        "a shown live list is not another session's grant: the shell's live-scope read shows both live grants"
    );
    for entry in both["capabilities"]
        .as_array()
        .expect("the shell live list holds a capabilities array")
    {
        assert!(
            entry.get("plan").is_none(),
            "a shown live list is not another session's grant: neither shell live entry carries a plan"
        );
    }

    let read_first = client_live(&stand_in, &first);
    assert_eq!(
        read_first, one_client,
        "a shown live list is not another session's grant: the first session's list is still only its own once grant"
    );
    assert!(
        read_first["capabilities"]
            .as_array()
            .expect("the first session's live list holds a capabilities array")
            .iter()
            .all(|entry| entry.get("session_id").is_none()),
        "a shown live list is not another session's grant: the first session's entry carries no session id"
    );
    assert!(
        !read_first.to_string().contains("request-2"),
        "a shown live list is not another session's grant: the first session's list does not hold the other session's grant"
    );

    let one_session = json!({
        "capabilities": [{
            "request_id": "request-2",
            "resource": "localhost://Public/plan-approval/a.txt",
            "action": "read",
            "duration": "session",
            "granted_at": 0,
        }]
    });
    let read_second = client_live(&stand_in, &second);
    assert_eq!(
        read_second, one_session,
        "a shown live list is not another session's grant: the second session's list holds its own session grant"
    );
    assert!(
        read_second.get("scope").is_none(),
        "a shown live list is not another session's grant: the second session's list carries no scope"
    );
    assert!(
        !read_second.to_string().contains("request-1"),
        "a shown live list is not another session's grant: the second session's list does not hold the first session's grant"
    );
    for entry in read_second["capabilities"]
        .as_array()
        .expect("the second session's live list holds a capabilities array")
    {
        for key in ["session_id", "plan"] {
            assert!(
                entry.get(key).is_none(),
                "a shown live list is not another session's grant: the second session's entry carries no {key}"
            );
        }
    }

    // Another session's use is refused and leaves both grants live.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &second_step,
            PLAN_B,
        ),
        Err((
            403,
            "wrong capsule: expected component-2, got component-1".to_owned()
        )),
        "a shown live list is not another session's grant: the first session does not spend the other session's grant"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        both,
        "a shown live list is not another session's grant: the refused use leaves both live grants"
    );

    // A spent once grant leaves the list; the session grant stays.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &first_step,
            PLAN_A,
        ),
        Ok(json!({ "valid": true })),
        "a shown live list is not another session's grant: the once grant authorises its one use"
    );
    let spent =
        json!({ "scope": "all_sessions_live", "capabilities": [both["capabilities"][1].clone()] });
    assert_eq!(
        shell_live(&stand_in, None),
        spent,
        "a shown live list is not another session's grant: the spent once grant leaves the shell live list"
    );
    assert_eq!(
        client_live(&stand_in, &first),
        empty_client,
        "a shown live list is not another session's grant: the spent once grant leaves the first session's live list"
    );
    assert_eq!(
        client_live(&stand_in, &second),
        one_session,
        "a shown live list is not another session's grant: the other session's session grant stays listed"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &first_step,
            PLAN_A,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown live list is not another session's grant: the spent once grant is no longer live"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        spent,
        "a shown live list is not another session's grant: the refused second use leaves the shell live list"
    );
    assert_eq!(
        client_live(&stand_in, &second),
        one_session,
        "a shown live list is not another session's grant: the refused second use leaves the session grant"
    );
    assert_eq!(
        client_live(&stand_in, &first),
        empty_client,
        "a shown live list is not another session's grant: the first session's live list stays empty"
    );

    // The session grant authorises its own session after one use and after two.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            &second_step,
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown live list is not another session's grant: the session grant authorises its session's use"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        spent,
        "a shown live list is not another session's grant: the session grant stays listed after one use"
    );
    assert_eq!(
        client_live(&stand_in, &second),
        one_session,
        "a shown live list is not another session's grant: the second session's list stays that one grant after one use"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            &second_step,
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown live list is not another session's grant: the session grant authorises a second use"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        spent,
        "a shown live list is not another session's grant: the session grant stays listed after two uses"
    );
    assert_eq!(
        client_live(&stand_in, &second),
        one_session,
        "a shown live list is not another session's grant: the second session's list stays that one grant after two uses"
    );

    // The stop drops that session's live grant and leaves the other session.
    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            &second,
            "stop the shown session"
        ),
        Ok(Value::Null),
        "a shown live list is not another session's grant: the shell stops the shown session"
    );
    let stopped = capsule(&stand_in, &second);
    assert_eq!(
        json!({
            "id": stopped["id"],
            "status": stopped["status"],
            "cause": stopped["cause"],
        }),
        json!({
            "id": "component-2",
            "status": "stopped",
            "cause": "stopped: stop the shown session",
        }),
        "a shown live list is not another session's grant: the stopped session records the stop cause"
    );
    let still_running = capsule(&stand_in, &first);
    assert_eq!(
        json!({
            "id": still_running["id"],
            "status": still_running["status"],
            "cause": still_running["cause"],
        }),
        json!({
            "id": "component-1",
            "status": "running",
            "cause": "",
        }),
        "a shown live list is not another session's grant: the other session stays running"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        empty_shell,
        "a shown live list is not another session's grant: the stop drops that session's live grant from the shell list"
    );
    assert_eq!(
        client_live(&stand_in, &first),
        empty_client,
        "a shown live list is not another session's grant: the first session's live list stays empty after the stop"
    );
    assert_eq!(
        client_live(&stand_in, &second),
        empty_client,
        "a shown live list is not another session's grant: the stopped session's live list is empty"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            &second_step,
            PLAN_B,
        ),
        Err((400, "grant is not live: Revoked".to_owned())),
        "a shown live list is not another session's grant: the stopped session's grant is revoked"
    );

    let granted_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    assert_eq!(
        record(&stand_in, &second, &second_step),
        granted_b,
        "a shown live list is not another session's grant: the stopped session's request record stays granted under the owner"
    );
    assert_eq!(
        record(&stand_in, &first, &first_step),
        granted_a,
        "a shown live list is not another session's grant: the first request record stays granted under the owner"
    );
    assert_eq!(
        shell_live(&stand_in, None),
        empty_shell,
        "a shown live list is not another session's grant: the shell live list stays empty after the stop"
    );
}

#[cfg(test)]
#[test]
fn shown_request_list_does_not_submit_again() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    fn capsule(stand_in: &StandIn, id: &str) -> Value {
        shell_capsules(stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id)
            .expect("the shell capsule list holds that id")
    }

    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let shell_only: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));
    let needs_session: Result<Value, (u16, String)> =
        Err((400, "requests need a session".to_owned()));

    let mut stand_in = StandIn::new();

    // A client is refused before the session is read, whatever session id it
    // gives and whether it gives one at all.
    for (caller, session) in [
        (
            Caller::Client {
                session_id: "component-1",
            },
            Some("component-1"),
        ),
        (
            Caller::Client {
                session_id: "component-2",
            },
            Some("component-1"),
        ),
        (Caller::Client { session_id: "" }, Some("")),
        (
            Caller::Client {
                session_id: "component-absent",
            },
            Some("component-absent"),
        ),
        (
            Caller::Client {
                session_id: "component-1",
            },
            None,
        ),
    ] {
        let read = read_shown_requests(&stand_in, caller, session);
        assert_eq!(
            read, shell_only,
            "a shown request list does not submit again: a client read is the shell refusal for {caller:?} with session {session:?}"
        );
        assert_ne!(
            read, needs_session,
            "a shown request list does not submit again: the client refusal is not the session refusal for {caller:?} with session {session:?}"
        );
        assert!(
            read.is_err(),
            "a shown request list does not submit again: the client read returns no body for {caller:?} with session {session:?}"
        );
        assert!(
            !matches!(&read, Ok(value) if value.to_string().contains("request-1")),
            "a shown request list does not submit again: the client refusal returns no body that names request-1 for {caller:?} with session {session:?}"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown request list does not submit again: the client read by {caller:?} leaves the capsule list empty"
        );
        assert_eq!(
            shell_live(&stand_in),
            empty_shell,
            "a shown request list does not submit again: the client read by {caller:?} leaves the shell live list empty"
        );
    }

    // A shell must name a session.
    for session in [None, Some("")] {
        let read = read_shown_requests(&stand_in, Caller::Shell, session);
        assert_eq!(
            read, needs_session,
            "a shown request list does not submit again: a shell read with session {session:?} needs a session"
        );
        assert_ne!(
            read, shell_only,
            "a shown request list does not submit again: the session refusal for {session:?} is not the shell refusal"
        );
        assert!(
            read.is_err(),
            "a shown request list does not submit again: the session refusal for {session:?} returns no body"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown request list does not submit again: the session refusal for {session:?} leaves the capsule list empty"
        );
        assert_eq!(
            shell_live(&stand_in),
            empty_shell,
            "a shown request list does not submit again: the session refusal for {session:?} leaves the shell live list empty"
        );
    }

    // A named session with no records is the empty list, including one that was
    // never launched.
    for session in ["component-absent", "component-1", "component-2"] {
        let read = read_shown_requests(&stand_in, Caller::Shell, Some(session));
        assert_eq!(
            read,
            Ok(empty_requests.clone()),
            "a shown request list does not submit again: the shell read for {session} on a fresh stand-in is the empty list"
        );
        assert_eq!(
            shell_capsules(&stand_in),
            Vec::<Value>::new(),
            "a shown request list does not submit again: the shell read for {session} leaves the capsule list empty"
        );
        assert_eq!(
            shell_live(&stand_in),
            empty_shell,
            "a shown request list does not submit again: the shell read for {session} leaves the shell live list empty"
        );
    }

    // Two running sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown request list does not submit again: the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "a shown request list does not submit again: the second running session is the stand-in's next component"
    );
    for id in [&first, &second] {
        let listed = capsule(&stand_in, id);
        assert_eq!(
            json!({
                "id": listed["id"],
                "status": listed["status"],
                "cause": listed["cause"],
            }),
            json!({
                "id": id,
                "status": "running",
                "cause": "",
            }),
            "a shown request list does not submit again: each launched session is running with no cause"
        );
    }

    // The launch stores no request, so both lists stay empty and a client read
    // stays refused.
    for session in [first.as_str(), second.as_str()] {
        assert_eq!(
            read_shown_requests(&stand_in, Caller::Shell, Some(session)),
            Ok(empty_requests.clone()),
            "a shown request list does not submit again: the shell read for {session} is still the empty list after the launch"
        );
    }
    assert_eq!(
        read_shown_requests(
            &stand_in,
            Caller::Client {
                session_id: &first,
            },
            Some(first.as_str()),
        ),
        shell_only,
        "a shown request list does not submit again: a client read stays the shell refusal after the launch"
    );

    let plan_a = plan_sha256(PLAN_A);
    assert_eq!(
        plan_a.len(),
        64,
        "a shown request list does not submit again: the shown hash of plan A is 64 characters"
    );
    let first_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the agent's submit stores the first shown plan");
    assert_eq!(
        first_step, "request-1",
        "a shown request list does not submit again: the first session's shown plan is the stand-in's first request"
    );
    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let first_pending = json!({ "requests": [pending_a.clone()] });
    let read_first = shell_requests(&stand_in, Some(first.as_str()));
    assert_eq!(
        read_first, first_pending,
        "a shown request list does not submit again: the shell read for the first session shows the pending step with its hash"
    );
    assert_eq!(
        read_first["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        1,
        "a shown request list does not submit again: the first session's list has one record"
    );
    assert_eq!(
        read_first["requests"][0]["plan"],
        json!(plan_a),
        "a shown request list does not submit again: the one record keeps the plan hash the owner was shown"
    );
    for session in [second.as_str(), "component-absent"] {
        assert_eq!(
            shell_requests(&stand_in, Some(session)),
            empty_requests.clone(),
            "a shown request list does not submit again: the first session's record is not in the list for {session}"
        );
    }

    // A second read of the same list returns the stored record and stores
    // nothing.
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_pending,
        "a shown request list does not submit again: a second shell read is still that one pending entry"
    );
    assert_eq!(
        read_shown_requests(
            &stand_in,
            Caller::Client {
                session_id: &first,
            },
            Some(first.as_str()),
        ),
        shell_only,
        "a shown request list does not submit again: the client read stays the shell refusal and is not that one-entry value"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: a pending record is not a live grant"
    );

    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_b.len(),
        64,
        "a shown request list does not submit again: the shown hash of plan B is 64 characters"
    );
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: &second,
        },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the other session's submit stores the second shown plan");
    assert_eq!(
        second_step, "request-2",
        "a shown request list does not submit again: the other session's shown plan is the stand-in's second request"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_pending,
        "a shown request list does not submit again: the first session's list still holds only its own record"
    );
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let second_pending = json!({ "requests": [pending_b.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_pending,
        "a shown request list does not submit again: the second session's list holds its own pending record"
    );
    assert!(
        !shell_requests(&stand_in, Some(second.as_str()))
            .to_string()
            .contains("request-1"),
        "a shown request list does not submit again: the second session's list holds no other session's record"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_pending,
        "a shown request list does not submit again: a second read of the second session is that same value"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: both pending records stay out of the shell live list"
    );

    // The owner's deny settles that record; the record stays on the list.
    assert_eq!(
        deny_shown_plan(
            &mut stand_in,
            Caller::Shell,
            &first_step,
            "deny the shown plan"
        ),
        Ok(json!({ "success": true })),
        "a shown request list does not submit again: the shell denies the first pending step"
    );
    let denied_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "denied",
        "decision_reason": "deny the shown plan",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let first_denied = json!({ "requests": [denied_a] });
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_denied,
        "a shown request list does not submit again: the denied record stays on the list with its settler"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_denied,
        "a shown request list does not submit again: a second read of the denied record is that same value"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_pending,
        "a shown request list does not submit again: the deny leaves the other session's record pending"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: the deny mints no live grant"
    );

    // The owner's grant settles the second record; the record stays granted.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &second_step, "once", &plan_b, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown request list does not submit again: the owner allows the second pending step once with the hash it saw"
    );
    let granted_b = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    let second_granted = json!({ "requests": [granted_b] });
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: the granted record stays on the list with its settler and hash"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: a second read of the granted record is that same value"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str()))["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        1,
        "a shown request list does not submit again: the granted session's list still has one record"
    );
    let one_grant = json!({
        "request_id": "request-2",
        "session_id": "component-2",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let shell_one = json!({ "scope": "all_sessions_live", "capabilities": [one_grant] });
    assert_eq!(
        shell_live(&stand_in),
        shell_one,
        "a shown request list does not submit again: the owner's grant is the one live entry"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: a third read is still that one granted entry"
    );
    assert_eq!(
        shell_live(&stand_in),
        shell_one,
        "a shown request list does not submit again: the third read leaves the live list as it was"
    );

    // The grant's use leaves the record granted and drops the spent grant.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            &second_step,
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown request list does not submit again: the once grant authorises its one use"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: the spent once grant stays granted on the list"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: the spent once grant leaves the shell live list"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: a second read after the use is that same granted record"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: the read after the use leaves the live list empty"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: &second,
            },
            &second_step,
            PLAN_B,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown request list does not submit again: the next use of the spent once grant is refused"
    );

    // A record's age settles it on the list; the settled records stay.
    let third_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    )
    .expect("the first session's second submit stores another shown plan");
    assert_eq!(
        third_step, "request-3",
        "a shown request list does not submit again: the first session's second shown plan is the stand-in's third request"
    );
    age_shown_plan(&mut stand_in, 300);
    let expired_a = json!({
        "request_id": "request-3",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "expired",
        "decision_reason": "Request timed out",
        "settled_by": "runtime",
        "plan": plan_a,
    });
    let first_settled = json!({
        "requests": [
            {
                "request_id": "request-1",
                "session_id": "component-1",
                "resource": "localhost://Public/plan-approval/a.txt",
                "action": "read",
                "reason": "",
                "status": "denied",
                "decision_reason": "deny the shown plan",
                "settled_by": "shell",
                "plan": plan_a,
            },
            expired_a,
        ],
    });
    let read_settled = shell_requests(&stand_in, Some(first.as_str()));
    assert_eq!(
        read_settled, first_settled,
        "a shown request list does not submit again: the denied and expired records stay on the list in request id order"
    );
    assert_eq!(
        read_settled["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        2,
        "a shown request list does not submit again: the first session's list has two records"
    );
    assert!(
        !read_settled.to_string().contains("request-2"),
        "a shown request list does not submit again: the first session's list holds no other session's record"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_settled,
        "a shown request list does not submit again: a second read after the expiry is that same value"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        second_granted,
        "a shown request list does not submit again: the other session's granted record is still on its list"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request list does not submit again: the expiry mints no live grant"
    );
    assert_eq!(
        read_shown_requests(&stand_in, Caller::Shell, None),
        needs_session,
        "a shown request list does not submit again: the shell still needs a session after the runs"
    );
}

#[cfg(test)]
#[test]
fn shown_submit_names_a_declared_ask() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let scheme_refusal: Result<String, (u16, String)> = Err((
        400,
        "Unsupported resource scheme. Allowed: elastos://, localhost://".to_owned(),
    ));
    let invalid_mint: Result<String, (u16, String)> = Err((
        400,
        "Invalid action: mint. Expected: read, write, execute, delete, message, admin".to_owned(),
    ));
    let invalid_execute: Result<String, (u16, String)> = Err((
        400,
        "Invalid action: execute. Expected: read, write, execute, delete, message, admin"
            .to_owned(),
    ));
    let shell_refusal: Result<String, (u16, String)> = Err((
        403,
        "capability request needs an instance session".to_owned(),
    ));

    let mut stand_in = StandIn::new();

    // The scheme check runs before the instance lookup, so a resource outside
    // the two allowed schemes is refused before any session is read.
    let unsupported_scheme = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        "https://Public/plan-approval/a.txt",
        "read",
        "",
    );
    assert_eq!(
        unsupported_scheme, scheme_refusal,
        "a shown submit names a declared ask: a resource outside elastos:// and localhost:// is the scheme refusal"
    );
    assert_ne!(
        unsupported_scheme,
        Err((
            403,
            "ask not declared in the signed manifest: https://Public/plan-approval/a.txt read"
                .to_owned()
        )),
        "a shown submit names a declared ask: the scheme refusal is not the declared-ask refusal"
    );
    assert_ne!(
        unsupported_scheme,
        Err((400, "unknown instance: component-1".to_owned())),
        "a shown submit names a declared ask: the scheme check runs before the instance lookup"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown submit names a declared ask: the scheme refusal stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown submit names a declared ask: the scheme refusal stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown submit names a declared ask: the scheme refusal mints no grant"
    );

    // The action allow-list also runs before the instance lookup, and its
    // refusal names the given word.
    let unknown_action = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "mint",
        "",
    );
    assert_eq!(
        unknown_action, invalid_mint,
        "a shown submit names a declared ask: an action outside the route's list is the action refusal"
    );
    assert_ne!(
        unknown_action,
        Err((
            403,
            "ask not declared in the signed manifest: localhost://Public/plan-approval/a.txt mint"
                .to_owned()
        )),
        "a shown submit names a declared ask: the action refusal is not the declared-ask refusal"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown submit names a declared ask: the action refusal stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown submit names a declared ask: the action refusal stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown submit names a declared ask: the action refusal mints no grant"
    );

    // Two running sessions come from the one launch journey.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown submit names a declared ask: the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "a shown submit names a declared ask: the second running session is the stand-in's next component"
    );
    for id in [&first, &second] {
        let listed = shell_capsules(&stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id.as_str())
            .expect("the shell capsule list holds that id");
        assert_eq!(
            json!({
                "id": listed["id"],
                "status": listed["status"],
                "cause": listed["cause"],
            }),
            json!({
                "id": id,
                "status": "running",
                "cause": "",
            }),
            "a shown submit names a declared ask: each launched session is running with no cause"
        );
    }

    // A pair the signed bundle did not declare is refused, and nothing is
    // stored: no prefix, no sibling path, no parent path and no other action.
    for (resource, action) in [
        ("localhost://Public/plan-approval/b.txt", "read"),
        ("localhost://Public/plan-approval/", "read"),
        ("localhost://Public/plan-approval/a.txt/extra", "read"),
        ("elastos://Public/plan-approval/a.txt", "read"),
        ("localhost://Public/plan-approval/a.txt", "execute"),
    ] {
        let result = request(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            PLAN_A,
            resource,
            action,
            "",
        );
        assert_eq!(
            result,
            Err((
                403,
                format!("ask not declared in the signed manifest: {resource} {action}")
            )),
            "a shown submit names a declared ask: the pair {resource} {action} is the declared-ask refusal"
        );
        assert!(
            result.is_err(),
            "a shown submit names a declared ask: the pair {resource} {action} stores no request id"
        );
        assert_ne!(
            result, scheme_refusal,
            "a shown submit names a declared ask: the declared-ask refusal for {resource} is not the scheme refusal"
        );
        assert_ne!(
            result, invalid_execute,
            "a shown submit names a declared ask: {action} is an allowed action, so the pair is refused for its ask"
        );
        assert_eq!(
            shell_requests(&stand_in, Some("component-1")),
            empty_requests,
            "a shown submit names a declared ask: the refused pair {resource} {action} stores no request"
        );
        assert_eq!(
            shell_live(&stand_in),
            empty_shell,
            "a shown submit names a declared ask: the refused pair {resource} {action} mints no grant"
        );
        assert_eq!(
            shell_capsules(&stand_in).len(),
            2,
            "a shown submit names a declared ask: the refused pair {resource} {action} leaves both capsules listed"
        );
    }

    // The caller and the instance lookup each refuse before the ask is read.
    let shell_submit = request(
        &mut stand_in,
        Caller::Shell,
        PLAN_A,
        "localhost://Public/plan-approval/b.txt",
        "read",
        "",
    );
    assert_eq!(
        shell_submit, shell_refusal,
        "a shown submit names a declared ask: a shell submit is the caller refusal"
    );
    assert_ne!(
        shell_submit,
        Err((
            403,
            "ask not declared in the signed manifest: localhost://Public/plan-approval/b.txt read"
                .to_owned()
        )),
        "a shown submit names a declared ask: the shell refusal is not the declared-ask refusal"
    );
    let absent_submit = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-absent",
        },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "read",
        "",
    );
    assert_eq!(
        absent_submit,
        Err((400, "unknown instance: component-absent".to_owned())),
        "a shown submit names a declared ask: a session with no instance is the instance refusal"
    );
    assert_ne!(
        absent_submit,
        Err((
            403,
            "ask not declared in the signed manifest: localhost://Public/plan-approval/a.txt read"
                .to_owned()
        )),
        "a shown submit names a declared ask: the instance lookup runs before the declared-ask check"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown submit names a declared ask: the refused submits leave the first session's list empty"
    );

    let plan_a = plan_sha256(PLAN_A);
    assert_eq!(
        plan_a.len(),
        64,
        "a shown submit names a declared ask: the shown hash of plan A is 64 characters"
    );
    let first_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/a.txt",
        "READ",
        "",
    )
    .expect("the agent's submit stores the declared ask");
    assert_eq!(
        first_step, "request-1",
        "a shown submit names a declared ask: the declared ask is the stand-in's first request"
    );
    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let first_pending = json!({ "requests": [pending_a.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_pending,
        "a shown submit names a declared ask: the stored request keeps the declared resource and lowercased action"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str()))["requests"][0]["action"],
        json!("read"),
        "a shown submit names a declared ask: READ is stored as read, not READ"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        first_pending,
        "a shown submit names a declared ask: a second read is that same pending entry"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        empty_requests.clone(),
        "a shown submit names a declared ask: the first session's record is not in the other session's list"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown submit names a declared ask: a pending request is not a live grant"
    );

    let plan_b = plan_sha256(PLAN_B);
    assert_eq!(
        plan_b.len(),
        64,
        "a shown submit names a declared ask: the shown hash of plan B is 64 characters"
    );
    let second_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_B,
        "localhost://Public/plan-approval/a.txt",
        "Write",
        "",
    )
    .expect("the agent's write submit stores the declared ask");
    assert_eq!(
        second_step, "request-2",
        "a shown submit names a declared ask: the write submit is the stand-in's second request"
    );
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "write",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let two_pending = json!({ "requests": [pending_a.clone(), pending_b.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        two_pending,
        "a shown submit names a declared ask: both pending records stay in request id order"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str()))["requests"][1]["action"],
        json!("write"),
        "a shown submit names a declared ask: Write is stored as write"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str()))["requests"][1]["status"],
        json!("pending"),
        "a shown submit names a declared ask: the write record is pending"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str()))["requests"][1]["plan"],
        json!(plan_b),
        "a shown submit names a declared ask: the write record keeps the plan hash the owner was shown"
    );

    let third_step = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/resident-instances/shared.txt",
        "read",
        "",
    )
    .expect("the agent's shared submit stores the declared ask");
    assert_eq!(
        third_step, "request-3",
        "a shown submit names a declared ask: the shared submit is the stand-in's third request"
    );
    let pending_shared = json!({
        "request_id": "request-3",
        "session_id": "component-1",
        "resource": "localhost://Public/resident-instances/shared.txt",
        "action": "read",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let three_pending = json!({
        "requests": [pending_a.clone(), pending_b.clone(), pending_shared.clone()],
    });
    let read_three = shell_requests(&stand_in, Some(first.as_str()));
    assert_eq!(
        read_three, three_pending,
        "a shown submit names a declared ask: the shared record is stored as its own resource"
    );
    assert_eq!(
        read_three["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        3,
        "a shown submit names a declared ask: the first session's list has three records"
    );
    assert_eq!(
        read_three["requests"][2]["resource"],
        json!("localhost://Public/resident-instances/shared.txt"),
        "a shown submit names a declared ask: the third record is the shared resource, not plan A's file"
    );
    assert_eq!(
        read_three["requests"][2]["action"],
        json!("read"),
        "a shown submit names a declared ask: the third record keeps its declared action"
    );
    assert_eq!(
        read_three["requests"][2]["status"],
        json!("pending"),
        "a shown submit names a declared ask: the third record is pending"
    );
    assert_eq!(
        read_three["requests"][2]["plan"],
        json!(plan_a),
        "a shown submit names a declared ask: the third record keeps the plan hash the owner was shown"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(second.as_str())),
        empty_requests.clone(),
        "a shown submit names a declared ask: the other session's list stays empty"
    );

    // A repeat of an undeclared pair is still the ask refusal and stores
    // nothing.
    let repeat = request(
        &mut stand_in,
        Caller::Client { session_id: &first },
        PLAN_A,
        "localhost://Public/plan-approval/b.txt",
        "read",
        "",
    );
    assert_eq!(
        repeat,
        Err((
            403,
            "ask not declared in the signed manifest: localhost://Public/plan-approval/b.txt read"
                .to_owned()
        )),
        "a shown submit names a declared ask: a repeat of the undeclared pair is still the ask refusal"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        three_pending,
        "a shown submit names a declared ask: the repeat refusal leaves the three stored records"
    );

    // The grant minted from the write request carries that action.
    assert_eq!(
        approve(&mut stand_in, Caller::Shell, &second_step, "once", &plan_b, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown submit names a declared ask: the owner allows the write request once with the hash it saw"
    );
    let one_grant = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "write",
        "duration": "once",
        "granted_at": 0,
    });
    let shell_one = json!({ "scope": "all_sessions_live", "capabilities": [one_grant] });
    assert_eq!(
        shell_live(&stand_in),
        shell_one,
        "a shown submit names a declared ask: the once grant carries the stored write action"
    );
    assert!(
        !shell_live(&stand_in).to_string().contains("request-1"),
        "a shown submit names a declared ask: the pending read request is not a live grant"
    );
    assert!(
        !shell_live(&stand_in).to_string().contains("request-3"),
        "a shown submit names a declared ask: the pending shared request is not a live grant"
    );

    let granted_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": "localhost://Public/plan-approval/a.txt",
        "action": "write",
        "reason": "",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_b,
    });
    let granted_three = json!({
        "requests": [pending_a.clone(), granted_b, pending_shared.clone()],
    });
    let read_granted = shell_requests(&stand_in, Some(first.as_str()));
    assert_eq!(
        read_granted, granted_three,
        "a shown submit names a declared ask: the write record is granted and the other two stay pending"
    );
    assert_eq!(
        read_granted["requests"][1]["action"],
        json!("write"),
        "a shown submit names a declared ask: the granted record keeps the write action"
    );
    assert_eq!(
        read_granted["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        3,
        "a shown submit names a declared ask: the first session's list still has three records"
    );

    // The grant's one use spends it and the shell live list empties.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &second_step,
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown submit names a declared ask: the once write grant authorises its one use"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown submit names a declared ask: the spent once grant leaves the live list"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client { session_id: &first },
            &second_step,
            PLAN_B,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown submit names a declared ask: the next use of the spent once grant is refused"
    );
    assert_eq!(
        shell_requests(&stand_in, Some(first.as_str())),
        json!({
            "requests": [pending_a, json!({
                "request_id": "request-2",
                "session_id": "component-1",
                "resource": "localhost://Public/plan-approval/a.txt",
                "action": "write",
                "reason": "",
                "status": "granted",
                "decision_reason": "owner approved",
                "settled_by": "shell",
                "plan": plan_b,
            }), pending_shared],
        }),
        "a shown submit names a declared ask: the records stay after the spend, with the write record granted"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown submit names a declared ask: the refused second use leaves the live list empty"
    );
}

#[cfg(test)]
#[test]
fn shown_request_reason_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn client_live(stand_in: &StandIn, session: &str) -> Value {
        read_shown_grants(
            stand_in,
            Caller::Client {
                session_id: session,
            },
            None,
        )
        .expect("the session reads its live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let resource_a = "localhost://Public/plan-approval/a.txt";
    let resource_b = "localhost://Public/plan-approval/b.txt";
    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let empty_client: Value = json!({ "capabilities": [] });
    let shell_refusal: Result<String, (u16, String)> = Err((
        403,
        "capability request needs an instance session".to_owned(),
    ));
    let ask_refusal_a: Result<String, (u16, String)> = Err((
        403,
        format!("ask not declared in the signed manifest: {resource_a} read"),
    ));
    let ask_refusal_b: Result<String, (u16, String)> = Err((
        403,
        format!("ask not declared in the signed manifest: {resource_b} read"),
    ));

    let mut stand_in = StandIn::new();

    // The reason travels with the caller and stores nothing on a refusal.
    let shell_submit = request(
        &mut stand_in,
        Caller::Shell,
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    );
    assert_eq!(
        shell_submit, shell_refusal,
        "a shown request reason is not the grant: a shell submit with a reason is the caller refusal"
    );
    assert_ne!(
        shell_submit, ask_refusal_a,
        "a shown request reason is not the grant: the shell refusal is not the declared-ask refusal"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown request reason is not the grant: the shell refusal stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown request reason is not the grant: the shell refusal stores no reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the shell refusal mints no grant"
    );

    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown request reason is not the grant: the fresh stand-in names the first running session component-1"
    );
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        second, "component-2",
        "a shown request reason is not the grant: the second running session is the stand-in's next component"
    );
    for id in [&first, &second] {
        let listed = shell_capsules(&stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id.as_str())
            .expect("the shell capsule list holds that id");
        assert_eq!(
            json!({
                "id": listed["id"],
                "status": listed["status"],
                "cause": listed["cause"],
            }),
            json!({
                "id": id,
                "status": "running",
                "cause": "",
            }),
            "a shown request reason is not the grant: each launched session is running with no cause"
        );
    }

    let absent_submit = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-absent",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    );
    assert_eq!(
        absent_submit,
        Err((400, "unknown instance: component-absent".to_owned())),
        "a shown request reason is not the grant: a session with no instance stores no reason"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown request reason is not the grant: the instance refusal leaves the first session's list empty"
    );

    let undeclared = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_b,
        "read",
        "approved",
    );
    assert_eq!(
        undeclared, ask_refusal_b,
        "a shown request reason is not the grant: a reason of approved with an undeclared ask stores nothing"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown request reason is not the grant: the declared-ask refusal stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the declared-ask refusal mints no grant"
    );
    assert_eq!(
        client_live(&stand_in, "component-1"),
        empty_client,
        "a shown request reason is not the grant: the declared-ask refusal leaves the client live list empty"
    );

    assert_eq!(
        plan_a.len(),
        64,
        "a shown request reason is not the grant: the shown hash of plan A is 64 characters"
    );
    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown request reason is not the grant: the first stored request is request-1"
    );
    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let one_pending = json!({ "requests": [pending_a.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown request reason is not the grant: the shell list shows the stated reason on the pending request"
    );

    let pending_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads its request status");
    assert_eq!(
        pending_status,
        json!({ "status": "pending" }),
        "a shown request reason is not the grant: a pending status body is the status word alone"
    );
    assert!(
        pending_status.get("reason").is_none(),
        "a shown request reason is not the grant: the pending status body has no reason key"
    );
    assert_ne!(
        pending_status,
        json!({ "status": "pending", "reason": "show this step" }),
        "a shown request reason is not the grant: the status body does not repeat the request reason"
    );

    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-1",
        ),
        Err((403, "Cannot access another session's request".to_owned())),
        "a shown request reason is not the grant: another session cannot read that request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: a pending request is not a live grant"
    );
    assert_eq!(
        client_live(&stand_in, "component-1"),
        empty_client,
        "a shown request reason is not the grant: the asking session sees no live grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown request reason is not the grant: a second shell read is that same pending entry"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        empty_requests,
        "a shown request reason is not the grant: the other session's list stays empty"
    );

    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_B,
        resource_a,
        "read",
        "approved",
    )
    .expect("the agent's request route stores the second pending request");
    assert_eq!(
        second_step, "request-2",
        "a shown request reason is not the grant: the reason approved stores a second pending request"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown request reason is not the grant: the shown hash of plan B is 64 characters"
    );
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let two_pending = json!({ "requests": [pending_a.clone(), pending_b.clone()] });
    let list_two = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        list_two, two_pending,
        "a shown request reason is not the grant: two pending rows stay in request id order"
    );
    assert_eq!(
        list_two["requests"][0]["reason"],
        json!("show this step"),
        "a shown request reason is not the grant: the first row keeps its stated reason"
    );
    assert_eq!(
        list_two["requests"][0]["status"],
        json!("pending"),
        "a shown request reason is not the grant: the first row stays pending"
    );
    assert_eq!(
        list_two["requests"][1]["reason"],
        json!("approved"),
        "a shown request reason is not the grant: the reason approved is stored as that text"
    );
    assert_eq!(
        list_two["requests"][1]["action"],
        json!("read"),
        "a shown request reason is not the grant: the second row keeps the read action"
    );

    let approved_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-2",
    )
    .expect("the owning session reads the second request status");
    assert_eq!(
        approved_status,
        json!({ "status": "pending" }),
        "a shown request reason is not the grant: the reason approved is a pending status"
    );
    assert_ne!(
        approved_status,
        json!({ "status": "granted" }),
        "a shown request reason is not the grant: the reason approved mints no grant"
    );
    assert!(
        approved_status.get("reason").is_none(),
        "a shown request reason is not the grant: the pending status body has no reason key"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the reason approved leaves the shell live list empty"
    );
    assert_eq!(
        client_live(&stand_in, "component-1"),
        empty_client,
        "a shown request reason is not the grant: the reason approved leaves the client live list empty"
    );

    let third_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "write",
        "",
    )
    .expect("the agent's request route stores the empty-reason request");
    assert_eq!(
        third_step, "request-3",
        "a shown request reason is not the grant: an empty reason stores the third pending request"
    );
    let pending_c = json!({
        "request_id": "request-3",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let three_pending = json!({
        "requests": [pending_a.clone(), pending_b.clone(), pending_c.clone()],
    });
    let list_three = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        list_three, three_pending,
        "a shown request reason is not the grant: the empty reason is stored as the empty string"
    );
    assert_eq!(
        list_three["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        3,
        "a shown request reason is not the grant: the first session's list has three records"
    );
    assert_eq!(
        list_three["requests"][2]["action"],
        json!("write"),
        "a shown request reason is not the grant: the third row keeps the write action"
    );
    assert_eq!(
        list_three["requests"][2]["reason"],
        json!(""),
        "a shown request reason is not the grant: an empty reason is stored as an empty string"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        empty_requests,
        "a shown request reason is not the grant: the other session's list stays empty"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the three pending reasons mint no grant"
    );

    let repeat = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_b,
        "read",
        "approved",
    );
    assert_eq!(
        repeat, ask_refusal_b,
        "a shown request reason is not the grant: a repeated undeclared ask is still the ask refusal"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        three_pending,
        "a shown request reason is not the grant: the repeat refusal leaves the three stored records"
    );

    assert_eq!(
        approve(&mut stand_in, Caller::Shell, "request-1", "once", &plan_a, "owner approved"),
        Ok(json!({ "success": true })),
        "a shown request reason is not the grant: the owner grants the read request once with the hash it saw"
    );
    let shell_grant = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let one_shell_grant = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_grant],
    });
    let shell_body = shell_live(&stand_in);
    assert_eq!(
        shell_body, one_shell_grant,
        "a shown request reason is not the grant: the live grant carries no request reason"
    );
    assert!(
        shell_body["capabilities"][0].get("reason").is_none(),
        "a shown request reason is not the grant: the shell live entry has no reason key"
    );
    let client_grant = json!({
        "request_id": "request-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let client_body = client_live(&stand_in, "component-1");
    assert_eq!(
        client_body,
        json!({ "capabilities": [client_grant] }),
        "a shown request reason is not the grant: the client live list omits the session and the reason"
    );
    assert!(
        client_body["capabilities"][0].get("session_id").is_none(),
        "a shown request reason is not the grant: the client live entry has no session id"
    );
    assert!(
        client_body["capabilities"][0].get("reason").is_none(),
        "a shown request reason is not the grant: the client live entry has no reason key"
    );

    let granted_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "granted",
        "decision_reason": "owner approved",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let granted_three = json!({
        "requests": [granted_a, pending_b.clone(), pending_c.clone()],
    });
    let list_granted = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        list_granted, granted_three,
        "a shown request reason is not the grant: the request keeps its reason after the owner grants"
    );
    assert_eq!(
        list_granted["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        3,
        "a shown request reason is not the grant: the granted record adds no request"
    );
    assert_eq!(
        list_granted["requests"][0]["reason"],
        json!("show this step"),
        "a shown request reason is not the grant: the granted record keeps show this step"
    );
    assert_eq!(
        list_granted["requests"][0]["status"],
        json!("granted"),
        "a shown request reason is not the grant: the first record is granted"
    );
    assert_eq!(
        list_granted["requests"][0]["settled_by"],
        json!("shell"),
        "a shown request reason is not the grant: the owner settles the request as shell"
    );
    assert_eq!(
        list_granted["requests"][0]["decision_reason"],
        json!("owner approved"),
        "a shown request reason is not the grant: the owner's approval reason is stored"
    );
    assert_eq!(
        list_granted["requests"][1]["status"],
        json!("pending"),
        "a shown request reason is not the grant: the approved reason stays pending"
    );
    assert_eq!(
        list_granted["requests"][1]["reason"],
        json!("approved"),
        "a shown request reason is not the grant: the second record keeps approved"
    );
    assert_eq!(
        list_granted["requests"][2]["status"],
        json!("pending"),
        "a shown request reason is not the grant: the empty reason stays pending"
    );
    assert_eq!(
        list_granted["requests"][2]["reason"],
        json!(""),
        "a shown request reason is not the grant: the third record keeps the empty reason"
    );

    let granted_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads the granted status");
    assert_eq!(
        granted_status,
        json!({ "status": "granted" }),
        "a shown request reason is not the grant: a granted status body is the status word alone"
    );
    assert!(
        granted_status.get("reason").is_none(),
        "a shown request reason is not the grant: the granted status body has no reason key"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-1",
            PLAN_A,
        ),
        Ok(json!({ "valid": true })),
        "a shown request reason is not the grant: the once grant authorises its one use"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the spent once grant leaves the live list"
    );
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-1",
            PLAN_A,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown request reason is not the grant: the next use of the spent once grant is refused"
    );
    let final_list = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        final_list, granted_three,
        "a shown request reason is not the grant: the three records stay after the spend"
    );
    assert_eq!(
        final_list["requests"][0]["reason"],
        json!("show this step"),
        "a shown request reason is not the grant: the spent grant leaves the request reason in place"
    );
    assert_eq!(
        final_list["requests"][0]["status"],
        json!("granted"),
        "a shown request reason is not the grant: the spent request record stays granted"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown request reason is not the grant: the refused second use leaves the live list empty"
    );
}

#[cfg(test)]
#[test]
fn shown_grant_rationale_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn client_live(stand_in: &StandIn, session: &str) -> Value {
        read_shown_grants(
            stand_in,
            Caller::Client {
                session_id: session,
            },
            None,
        )
        .expect("the session reads its live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let resource_a = "localhost://Public/plan-approval/a.txt";
    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let empty_client: Value = json!({ "capabilities": [] });
    let shell_refusal: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));
    let mismatched_plan: Result<Value, (u16, String)> = Err((
        403,
        "approved plan does not match the requested plan".to_owned(),
    ));

    let mut stand_in = StandIn::new();

    // A client never reaches the grant body, even before any request exists.
    let early_client = approve(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        "once",
        &plan_a,
        "approved",
    );
    assert_eq!(
        early_client, shell_refusal,
        "a shown grant rationale is not the grant: a client approval is the shell-only refusal"
    );
    assert_ne!(
        early_client,
        Err((
            400,
            "Invalid duration: standing. Expected 'once' or 'session'".to_owned()
        )),
        "a shown grant rationale is not the grant: the client refusal is not an invalid-duration refusal"
    );
    assert_ne!(
        early_client,
        Err((400, "unknown request: request-1".to_owned())),
        "a shown grant rationale is not the grant: the client refusal does not consult the request id"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown grant rationale is not the grant: a refused client approval stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown grant rationale is not the grant: a refused client approval stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown grant rationale is not the grant: a refused client approval mints no grant"
    );

    // Two sessions run, and the first posts the plan the owner will see.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown grant rationale is not the grant: the fresh stand-in names the first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "a shown grant rationale is not the grant: the second running session is component-2"
    );
    for id in [&first, &second] {
        let listed = shell_capsules(&stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id.as_str())
            .expect("the shell capsule list holds that id");
        assert_eq!(
            json!({
                "id": listed["id"],
                "status": listed["status"],
                "cause": listed["cause"],
            }),
            json!({
                "id": id,
                "status": "running",
                "cause": "",
            }),
            "a shown grant rationale is not the grant: each launched session runs with no cause"
        );
    }

    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown grant rationale is not the grant: the first stored request is request-1"
    );
    assert_eq!(
        plan_a.len(),
        64,
        "a shown grant rationale is not the grant: the hash of plan A has length 64"
    );

    // The session that asked is not the shell, so it still mints nothing.
    let asking_client = approve(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        "once",
        &plan_a,
        "approved",
    );
    assert_eq!(
        asking_client, shell_refusal,
        "a shown grant rationale is not the grant: the asking session's approval is the shell-only refusal"
    );
    assert_ne!(
        asking_client, mismatched_plan,
        "a shown grant rationale is not the grant: the asking session's refusal is not the plan-hash refusal"
    );

    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let one_pending = json!({ "requests": [pending_a.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown grant rationale is not the grant: the request reason is shown on the pending row"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown grant rationale is not the grant: the pending row is not a live grant"
    );
    assert_eq!(
        client_live(&stand_in, "component-1"),
        empty_client,
        "a shown grant rationale is not the grant: the asking session holds no live grant"
    );

    // A refused duration stores and mints nothing.
    let invalid_duration = approve(
        &mut stand_in,
        Caller::Shell,
        "request-1",
        "standing",
        &plan_a,
        "approved",
    );
    assert_eq!(
        invalid_duration,
        Err((
            400,
            "Invalid duration: standing. Expected 'once' or 'session'".to_owned()
        )),
        "a shown grant rationale is not the grant: the refused duration word is the route's own refusal"
    );
    assert_ne!(
        invalid_duration, shell_refusal,
        "a shown grant rationale is not the grant: the shell reaches the duration refusal"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown grant rationale is not the grant: the refused duration leaves the row pending"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown grant rationale is not the grant: the refused duration mints no grant"
    );

    // A mismatched hash stores and mints nothing.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-1",
            "once",
            &plan_b,
            "approved"
        ),
        mismatched_plan,
        "a shown grant rationale is not the grant: the owner's hash must be the shown request's hash"
    );
    let refused_hash_list = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        refused_hash_list, one_pending,
        "a shown grant rationale is not the grant: the refused hash leaves the row pending"
    );
    assert_eq!(
        refused_hash_list["requests"][0]["decision_reason"],
        json!(""),
        "a shown grant rationale is not the grant: the refused hash stores no decision reason"
    );
    assert_eq!(
        refused_hash_list["requests"][0]["reason"],
        json!("show this step"),
        "a shown grant rationale is not the grant: the refused hash leaves the request reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown grant rationale is not the grant: the refused hash mints no grant"
    );

    // An unknown request id stores and mints nothing.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-missing",
            "once",
            &plan_a,
            "approved"
        ),
        Err((400, "unknown request: request-missing".to_owned())),
        "a shown grant rationale is not the grant: an unknown request id is refused by that id"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown grant rationale is not the grant: the unknown id leaves the row pending"
    );

    // The owner's stated rationale settles the shown request and mints once.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-1",
            "once",
            &plan_a,
            "show this grant"
        ),
        Ok(json!({ "success": true })),
        "a shown grant rationale is not the grant: the shell approval succeeds"
    );
    let granted_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "granted",
        "decision_reason": "show this grant",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let one_granted = json!({ "requests": [granted_a.clone()] });
    let granted_list = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        granted_list, one_granted,
        "a shown grant rationale is not the grant: the stated rationale is the decision reason"
    );
    assert_eq!(
        granted_list["requests"][0]["reason"],
        json!("show this step"),
        "a shown grant rationale is not the grant: the request keeps its own reason"
    );
    assert_eq!(
        granted_list["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown grant rationale is not the grant: the rationale is stored as the decision reason"
    );

    let granted_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads the granted status");
    assert_eq!(
        granted_status,
        json!({ "status": "granted" }),
        "a shown grant rationale is not the grant: a granted status body is the status word alone"
    );
    assert!(
        granted_status.get("reason").is_none(),
        "a shown grant rationale is not the grant: the granted status body has no reason key"
    );
    assert_ne!(
        granted_status,
        json!({ "status": "granted", "reason": "show this grant" }),
        "a shown grant rationale is not the grant: the status body does not repeat the decision reason"
    );

    let shell_entry_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let one_shell_grant = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_a.clone()],
    });
    let shell_body = shell_live(&stand_in);
    assert_eq!(
        shell_body, one_shell_grant,
        "a shown grant rationale is not the grant: the live grant carries no rationale"
    );
    assert!(
        shell_body["capabilities"][0].get("rationale").is_none(),
        "a shown grant rationale is not the grant: the shell live entry has no rationale key"
    );
    assert!(
        shell_body["capabilities"][0]
            .get("decision_reason")
            .is_none(),
        "a shown grant rationale is not the grant: the shell live entry has no decision reason key"
    );

    let client_entry_a = json!({
        "request_id": "request-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let client_body = client_live(&stand_in, "component-1");
    assert_eq!(
        client_body,
        json!({ "capabilities": [client_entry_a] }),
        "a shown grant rationale is not the grant: the client live entry omits the session and the rationale"
    );
    assert!(
        client_body["capabilities"][0].get("session_id").is_none(),
        "a shown grant rationale is not the grant: the client live entry has no session id"
    );
    assert!(
        client_body["capabilities"][0].get("rationale").is_none(),
        "a shown grant rationale is not the grant: the client live entry has no rationale key"
    );
    assert!(
        client_body["capabilities"][0]
            .get("decision_reason")
            .is_none(),
        "a shown grant rationale is not the grant: the client live entry has no decision reason key"
    );
    assert_eq!(
        client_live(&stand_in, "component-2"),
        empty_client,
        "a shown grant rationale is not the grant: the other session sees no grant"
    );

    // A second approval settles nothing and keeps the first decision reason.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-1",
            "once",
            &plan_a,
            "approved"
        ),
        Err((400, "request is not pending: request-1".to_owned())),
        "a shown grant rationale is not the grant: a granted request cannot be approved again"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_granted,
        "a shown grant rationale is not the grant: the repeat approval leaves the granted row"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown grant rationale is not the grant: the repeat approval keeps the first decision reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown grant rationale is not the grant: the repeat approval keeps the one live grant"
    );

    // A rationale of session with duration once stays the decision reason while
    // the grant duration is once.
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_B,
        resource_a,
        "read",
        "approved",
    )
    .expect("the agent's request route stores the second pending request");
    assert_eq!(
        second_step, "request-2",
        "a shown grant rationale is not the grant: the second stored request is request-2"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown grant rationale is not the grant: the hash of plan B has length 64"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-2",
            "once",
            &plan_b,
            "session"
        ),
        Ok(json!({ "success": true })),
        "a shown grant rationale is not the grant: the second shell approval succeeds"
    );
    let granted_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "granted",
        "decision_reason": "session",
        "settled_by": "shell",
        "plan": plan_b,
    });
    let two_granted = json!({ "requests": [granted_a.clone(), granted_b] });
    let two_rows = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        two_rows["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        2,
        "a shown grant rationale is not the grant: the granted requests are two rows"
    );
    assert_eq!(
        two_rows, two_granted,
        "a shown grant rationale is not the grant: each granted row keeps its own reason"
    );
    assert_eq!(
        two_rows["requests"][1]["reason"],
        json!("approved"),
        "a shown grant rationale is not the grant: the second row keeps its request reason"
    );
    assert_eq!(
        two_rows["requests"][1]["decision_reason"],
        json!("session"),
        "a shown grant rationale is not the grant: the rationale session is the decision reason"
    );
    assert_eq!(
        two_rows["requests"][1]["settled_by"],
        json!("shell"),
        "a shown grant rationale is not the grant: the shell settles the second row"
    );
    assert_eq!(
        two_rows["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown grant rationale is not the grant: the first decision reason survives the second grant"
    );

    let shell_entry_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let two_shell_grants = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_a.clone(), shell_entry_b.clone()],
    });
    let two_live = shell_live(&stand_in);
    assert_eq!(
        two_live, two_shell_grants,
        "a shown grant rationale is not the grant: the session rationale does not change the once duration"
    );
    assert_eq!(
        two_live["capabilities"][1]["duration"],
        json!("once"),
        "a shown grant rationale is not the grant: the second live grant lasts once"
    );
    for entry in two_live["capabilities"]
        .as_array()
        .expect("the shell live body holds a capabilities array")
    {
        assert!(
            entry.get("rationale").is_none(),
            "a shown grant rationale is not the grant: no live entry carries a rationale"
        );
    }

    // An empty rationale is stored as the empty string, not a default.
    let third_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_A,
        resource_a,
        "write",
        "",
    )
    .expect("the agent's request route stores the empty-reason request");
    assert_eq!(
        third_step, "request-3",
        "a shown grant rationale is not the grant: the third stored request is request-3"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-3",
            "once",
            &plan_a,
            ""
        ),
        Ok(json!({ "success": true })),
        "a shown grant rationale is not the grant: the shell approval with an empty rationale succeeds"
    );
    let granted_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "granted",
        "decision_reason": "",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let second_session_rows = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        second_session_rows,
        json!({ "requests": [granted_c] }),
        "a shown grant rationale is not the grant: an empty rationale is stored as the empty string"
    );
    assert_eq!(
        second_session_rows["requests"][0]["decision_reason"],
        json!(""),
        "a shown grant rationale is not the grant: the empty rationale stays empty"
    );
    assert_ne!(
        second_session_rows["requests"][0]["decision_reason"],
        json!("Shell auto-grant"),
        "a shown grant rationale is not the grant: the empty rationale is not the route's missing-value default"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        two_granted,
        "a shown grant rationale is not the grant: the first session's two rows stay"
    );

    let shell_entry_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "duration": "once",
        "granted_at": 0,
    });
    let three_shell_grants = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_a.clone(), shell_entry_b.clone(), shell_entry_c.clone()],
    });
    let three_live = shell_live(&stand_in);
    assert_eq!(
        three_live, three_shell_grants,
        "a shown grant rationale is not the grant: the empty rationale adds no grant text"
    );
    assert!(
        three_live["capabilities"][2].get("rationale").is_none(),
        "a shown grant rationale is not the grant: the third live entry has no rationale key"
    );

    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-3",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown grant rationale is not the grant: the third granted status is the status word alone"
    );
    assert!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-3",
        )
        .expect("the owning session reads the granted status")
        .get("reason")
        .is_none(),
        "a shown grant rationale is not the grant: the third status body has no reason key"
    );

    // One use spends the once grant while the decision reason stays.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-1",
            PLAN_A,
        ),
        Ok(json!({ "valid": true })),
        "a shown grant rationale is not the grant: the once grant authorises its one use"
    );
    let two_live_after_spend = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_b.clone(), shell_entry_c.clone()],
    });
    assert_eq!(
        shell_live(&stand_in),
        two_live_after_spend,
        "a shown grant rationale is not the grant: the spent once grant leaves the live list"
    );
    let spent_rows = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        spent_rows, two_granted,
        "a shown grant rationale is not the grant: the request rows stay after the spend"
    );
    assert_eq!(
        spent_rows["requests"][0]["status"],
        json!("granted"),
        "a shown grant rationale is not the grant: the spent request stays granted"
    );
    assert_eq!(
        spent_rows["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown grant rationale is not the grant: the spent grant keeps its decision reason"
    );
    assert_eq!(
        spent_rows["requests"][0]["reason"],
        json!("show this step"),
        "a shown grant rationale is not the grant: the spent grant keeps the request reason"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-1",
            PLAN_A,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown grant rationale is not the grant: the next use of the spent once grant is refused"
    );
    let after_refusal_rows = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        after_refusal_rows, two_granted,
        "a shown grant rationale is not the grant: the refused second use leaves the two rows"
    );
    assert_eq!(
        after_refusal_rows["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown grant rationale is not the grant: the refused second use keeps the decision reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        two_live_after_spend,
        "a shown grant rationale is not the grant: the refused second use leaves the live list"
    );
}

#[cfg(test)]
#[test]
fn shown_deny_reason_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn client_live(stand_in: &StandIn, session: &str) -> Value {
        read_shown_grants(
            stand_in,
            Caller::Client {
                session_id: session,
            },
            None,
        )
        .expect("the session reads its live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    fn running_without_cause(stand_in: &StandIn, id: &str) -> Value {
        let listed = shell_capsules(stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id)
            .expect("the shell capsule list holds that id");
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let resource_a = "localhost://Public/plan-approval/a.txt";
    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let empty_client: Value = json!({ "capabilities": [] });
    let shell_refusal: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));

    let mut stand_in = StandIn::new();

    // A client never reaches the deny body, even before any request exists.
    let early_client = deny_shown_plan(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        "approved",
    );
    assert_eq!(
        early_client, shell_refusal,
        "a shown deny reason is not the grant: a client deny is the shell-only refusal"
    );
    assert_ne!(
        early_client,
        Err((400, "unknown request: request-1".to_owned())),
        "a shown deny reason is not the grant: the client refusal does not consult the request id"
    );
    assert_ne!(
        early_client,
        Err((400, "Denied by user".to_owned())),
        "a shown deny reason is not the grant: the client refusal is not a stored deny reason"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown deny reason is not the grant: a refused client deny stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown deny reason is not the grant: a refused client deny stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: a refused client deny mints no grant"
    );

    // Two sessions run, and the first posts the plans the owner will see.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown deny reason is not the grant: the fresh stand-in names the first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "a shown deny reason is not the grant: the second running session is component-2"
    );
    for id in [&first, &second] {
        assert_eq!(
            running_without_cause(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown deny reason is not the grant: each launched session runs with no cause"
        );
    }

    // A client deny of an absent id is the same refusal, and stores nothing.
    let absent_client = deny_shown_plan(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-absent",
        "approved",
    );
    assert_eq!(
        absent_client, shell_refusal,
        "a shown deny reason is not the grant: a client deny of an absent id is the shell-only refusal"
    );
    assert_ne!(
        absent_client,
        Err((400, "unknown request: request-absent".to_owned())),
        "a shown deny reason is not the grant: the client refusal does not consult an absent id"
    );
    assert_eq!(
        shell_capsules(&stand_in).len(),
        2,
        "a shown deny reason is not the grant: the refused client deny leaves both capsules"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown deny reason is not the grant: the refused absent-id deny stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the refused absent-id deny mints no grant"
    );

    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown deny reason is not the grant: the first stored request is request-1"
    );
    assert_eq!(
        plan_a.len(),
        64,
        "a shown deny reason is not the grant: the hash of plan A has length 64"
    );

    // The asking session's deny mints nothing and settles nothing.
    let asking_client = deny_shown_plan(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        "approved",
    );
    assert_eq!(
        asking_client, shell_refusal,
        "a shown deny reason is not the grant: the asking session's deny is the shell-only refusal"
    );
    assert_ne!(
        asking_client,
        Err((400, "request is not pending: request-1".to_owned())),
        "a shown deny reason is not the grant: the client refusal is not a settlement refusal"
    );

    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let one_pending = json!({ "requests": [pending_a.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown deny reason is not the grant: the refused client deny leaves the step pending"
    );
    let pending_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads the pending status");
    assert_eq!(
        pending_status,
        json!({ "status": "pending" }),
        "a shown deny reason is not the grant: a pending status body is the status word alone"
    );
    assert!(
        pending_status.get("reason").is_none(),
        "a shown deny reason is not the grant: the pending status body has no reason key"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the pending step is not a live grant"
    );

    // An unknown id from the shell stores nothing and mints nothing.
    let unknown_shell = deny_shown_plan(
        &mut stand_in,
        Caller::Shell,
        "request-missing",
        "do not run this",
    );
    assert_eq!(
        unknown_shell,
        Err((400, "unknown request: request-missing".to_owned())),
        "a shown deny reason is not the grant: the shell's unknown id is refused by that id"
    );
    assert_ne!(
        unknown_shell, shell_refusal,
        "a shown deny reason is not the grant: the shell reaches the unknown-request refusal"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown deny reason is not the grant: the unknown id leaves the step pending"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0]["decision_reason"],
        json!(""),
        "a shown deny reason is not the grant: the unknown id stores no decision reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the unknown id mints no grant"
    );

    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_B,
        resource_a,
        "read",
        "approved",
    )
    .expect("the agent's request route stores the second pending request");
    assert_eq!(
        second_step, "request-2",
        "a shown deny reason is not the grant: the second stored request is request-2"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown deny reason is not the grant: the hash of plan B has length 64"
    );

    // The owner's stated deny reason settles the shown request and mints nothing.
    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, "request-1", "do not run this"),
        Ok(json!({ "success": true })),
        "a shown deny reason is not the grant: the shell deny succeeds"
    );
    let denied_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "denied",
        "decision_reason": "do not run this",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let denied_and_pending = json!({ "requests": [denied_a.clone(), pending_b.clone()] });
    let two_rows = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        two_rows, denied_and_pending,
        "a shown deny reason is not the grant: the stated reason is the decision reason while the sibling stays pending"
    );
    assert_eq!(
        two_rows["requests"][0]["reason"],
        json!("show this step"),
        "a shown deny reason is not the grant: the denied request keeps its own reason"
    );
    assert_eq!(
        two_rows["requests"][0]["decision_reason"],
        json!("do not run this"),
        "a shown deny reason is not the grant: the stated reason is stored as the decision reason"
    );
    assert_eq!(
        two_rows["requests"][1]["status"],
        json!("pending"),
        "a shown deny reason is not the grant: the sibling with reason approved stays pending"
    );
    assert_eq!(
        two_rows["requests"][1]["decision_reason"],
        json!(""),
        "a shown deny reason is not the grant: the sibling stores no decision reason"
    );

    let denied_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads the denied status");
    assert_eq!(
        denied_status,
        json!({ "status": "denied", "reason": "do not run this" }),
        "a shown deny reason is not the grant: a denied status body is the status word plus the decision reason"
    );
    assert_ne!(
        denied_status,
        json!({ "status": "granted" }),
        "a shown deny reason is not the grant: the denied status is not a grant"
    );
    assert_ne!(
        denied_status,
        json!({ "status": "denied" }),
        "a shown deny reason is not the grant: the denied status body carries its reason"
    );
    assert_ne!(
        denied_status,
        json!({ "status": "denied", "reason": "show this step" }),
        "a shown deny reason is not the grant: the status reason is the decision reason, not the request reason"
    );
    assert_ne!(
        denied_status,
        json!({ "status": "denied", "reason": "deny the shown plan" }),
        "a shown deny reason is not the grant: the status reason is the stated reason, not a helper default"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-1",
        ),
        Err((403, "Cannot access another session's request".to_owned())),
        "a shown deny reason is not the grant: the other session cannot read the denied status"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: a denied step is not a live grant"
    );
    assert_eq!(
        client_live(&stand_in, "component-1"),
        empty_client,
        "a shown deny reason is not the grant: the asking session holds no live grant"
    );
    for id in [&first, &second] {
        assert_eq!(
            running_without_cause(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown deny reason is not the grant: the shell deny leaves each session running with no cause"
        );
    }

    // A second deny of the settled request stores nothing new.
    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, "request-1", "approved"),
        Err((400, "request is not pending: request-1".to_owned())),
        "a shown deny reason is not the grant: a denied request cannot be denied again"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        denied_and_pending,
        "a shown deny reason is not the grant: the repeat deny leaves the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0]["decision_reason"],
        json!("do not run this"),
        "a shown deny reason is not the grant: the repeat deny keeps the first decision reason"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][1]["status"],
        json!("pending"),
        "a shown deny reason is not the grant: the repeat deny leaves the sibling pending"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the repeat deny mints no grant"
    );

    // A reason that reads like a grant still stores a deny and mints nothing.
    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, "request-2", "granted"),
        Ok(json!({ "success": true })),
        "a shown deny reason is not the grant: a deny with reason granted succeeds"
    );
    let denied_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "denied",
        "decision_reason": "granted",
        "settled_by": "shell",
        "plan": plan_b,
    });
    let two_denied = json!({ "requests": [denied_a.clone(), denied_b.clone()] });
    let denied_rows = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        denied_rows["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        2,
        "a shown deny reason is not the grant: the two denials leave two rows"
    );
    assert_eq!(
        denied_rows, two_denied,
        "a shown deny reason is not the grant: each denied row keeps its own decision reason"
    );
    assert_eq!(
        denied_rows["requests"][1]["reason"],
        json!("approved"),
        "a shown deny reason is not the grant: the second row keeps its request reason"
    );
    assert_eq!(
        denied_rows["requests"][1]["status"],
        json!("denied"),
        "a shown deny reason is not the grant: a reason of granted stores status denied"
    );
    assert_eq!(
        denied_rows["requests"][1]["decision_reason"],
        json!("granted"),
        "a shown deny reason is not the grant: the reason granted is stored as the decision reason"
    );
    assert_eq!(
        denied_rows["requests"][1]["settled_by"],
        json!("shell"),
        "a shown deny reason is not the grant: the shell settles the second row"
    );
    assert_eq!(
        denied_rows["requests"][0]["decision_reason"],
        json!("do not run this"),
        "a shown deny reason is not the grant: the first decision reason survives the second deny"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "granted" })),
        "a shown deny reason is not the grant: a deny with reason granted reads as denied"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown deny reason is not the grant: the reason granted is not a granted status"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "approved" })),
        "a shown deny reason is not the grant: the status reason is the decision reason, not the request reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the reason granted mints no grant"
    );

    // An empty stated reason is stored as the empty string, not a default.
    let third_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_A,
        resource_a,
        "write",
        "",
    )
    .expect("the agent's request route stores the empty-reason request");
    assert_eq!(
        third_step, "request-3",
        "a shown deny reason is not the grant: the third stored request is request-3"
    );
    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, "request-3", ""),
        Ok(json!({ "success": true })),
        "a shown deny reason is not the grant: a deny with an empty reason succeeds"
    );
    let denied_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "denied",
        "decision_reason": "",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let one_denied_c = json!({ "requests": [denied_c] });
    let second_session_rows = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        second_session_rows, one_denied_c,
        "a shown deny reason is not the grant: an empty reason is stored as the empty string"
    );
    assert_eq!(
        second_session_rows["requests"][0]["decision_reason"],
        json!(""),
        "a shown deny reason is not the grant: the empty reason stays empty"
    );
    assert_ne!(
        second_session_rows["requests"][0]["decision_reason"],
        json!("Denied by user"),
        "a shown deny reason is not the grant: the empty reason is not the route's missing-value default"
    );
    assert_ne!(
        second_session_rows["requests"][0]["decision_reason"],
        json!("deny the shown plan"),
        "a shown deny reason is not the grant: the empty reason is not the earlier helper text"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-3",
        ),
        Ok(json!({ "status": "denied", "reason": "" })),
        "a shown deny reason is not the grant: the empty reason is the denied status reason"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-3",
        ),
        Ok(json!({ "status": "denied", "reason": "Denied by user" })),
        "a shown deny reason is not the grant: the empty reason is not the missing-value default"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        two_denied,
        "a shown deny reason is not the grant: the first session's two rows stay"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the empty reason mints no grant"
    );
    for id in [&first, &second] {
        assert_eq!(
            running_without_cause(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown deny reason is not the grant: the empty-reason deny leaves each session running with no cause"
        );
    }

    // A deny of a granted request stores none of it and leaves the live grant.
    let fourth_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_B,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores the grantable request");
    assert_eq!(
        fourth_step, "request-4",
        "a shown deny reason is not the grant: the fourth stored request is request-4"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-4",
            "once",
            &plan_b,
            "show this grant"
        ),
        Ok(json!({ "success": true })),
        "a shown deny reason is not the grant: the shell approval succeeds"
    );
    assert_eq!(
        deny_shown_plan(&mut stand_in, Caller::Shell, "request-4", "do not run this"),
        Err((400, "request is not pending: request-4".to_owned())),
        "a shown deny reason is not the grant: a granted request cannot be denied"
    );
    let granted_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "denied",
        "decision_reason": "",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let granted_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "granted",
        "decision_reason": "show this grant",
        "settled_by": "shell",
        "plan": plan_b,
    });
    let two_second_session = json!({ "requests": [granted_c, granted_d.clone()] });
    let second_rows = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        second_rows["requests"]
            .as_array()
            .expect("the shell request list holds a requests array")
            .len(),
        2,
        "a shown deny reason is not the grant: the refused deny leaves two rows"
    );
    assert_eq!(
        second_rows, two_second_session,
        "a shown deny reason is not the grant: the granted row keeps its own decision reason"
    );
    assert_eq!(
        second_rows["requests"][0]["status"],
        json!("denied"),
        "a shown deny reason is not the grant: the earlier denied row stays denied"
    );
    assert_eq!(
        second_rows["requests"][0]["decision_reason"],
        json!(""),
        "a shown deny reason is not the grant: the earlier denied row keeps its empty decision reason"
    );
    assert_eq!(
        second_rows["requests"][1]["reason"],
        json!("show this step"),
        "a shown deny reason is not the grant: the granted row keeps its request reason"
    );
    assert_eq!(
        second_rows["requests"][1]["action"],
        json!("read"),
        "a shown deny reason is not the grant: the granted row keeps its action"
    );
    assert_eq!(
        second_rows["requests"][1]["decision_reason"],
        json!("show this grant"),
        "a shown deny reason is not the grant: the refused deny leaves the grant rationale"
    );
    assert_ne!(
        second_rows["requests"][1]["decision_reason"],
        json!("do not run this"),
        "a shown deny reason is not the grant: the refused deny stores none of its reason"
    );
    assert_ne!(
        second_rows["requests"][1]["status"],
        json!("denied"),
        "a shown deny reason is not the grant: the refused deny leaves the row granted"
    );

    let granted_status = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        "request-4",
    )
    .expect("the owning session reads the granted status");
    assert_eq!(
        granted_status,
        json!({ "status": "granted" }),
        "a shown deny reason is not the grant: the granted status body is the status word alone"
    );
    assert!(
        granted_status.get("reason").is_none(),
        "a shown deny reason is not the grant: the granted status body has no reason key"
    );
    assert_ne!(
        granted_status,
        json!({ "status": "denied", "reason": "do not run this" }),
        "a shown deny reason is not the grant: the refused deny leaves no denied status"
    );

    let shell_entry_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let one_shell_grant = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_d],
    });
    let shell_body = shell_live(&stand_in);
    assert_eq!(
        shell_body, one_shell_grant,
        "a shown deny reason is not the grant: the refused deny leaves the live once grant"
    );
    assert!(
        shell_body["capabilities"][0].get("rationale").is_none(),
        "a shown deny reason is not the grant: the shell live entry has no rationale key"
    );
    assert!(
        shell_body["capabilities"][0]
            .get("decision_reason")
            .is_none(),
        "a shown deny reason is not the grant: the shell live entry has no decision reason key"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        two_denied,
        "a shown deny reason is not the grant: the first session's two denied rows stay"
    );

    // One use spends that once grant while the decision reason stays.
    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
            PLAN_B,
        ),
        Ok(json!({ "valid": true })),
        "a shown deny reason is not the grant: the live once grant authorises its one use"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the spent once grant leaves the live list"
    );
    let spent_rows = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        spent_rows, two_second_session,
        "a shown deny reason is not the grant: the request rows stay after the spend"
    );
    assert_eq!(
        spent_rows["requests"][1]["status"],
        json!("granted"),
        "a shown deny reason is not the grant: the spent request stays granted"
    );
    assert_eq!(
        spent_rows["requests"][1]["decision_reason"],
        json!("show this grant"),
        "a shown deny reason is not the grant: the spent grant keeps its decision reason"
    );

    assert_eq!(
        execute(
            &mut stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
            PLAN_B,
        ),
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown deny reason is not the grant: the next use of the spent once grant is refused"
    );
    let after_refusal_rows = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        after_refusal_rows, two_second_session,
        "a shown deny reason is not the grant: the refused second use leaves the two rows"
    );
    assert_eq!(
        after_refusal_rows["requests"][1]["status"],
        json!("granted"),
        "a shown deny reason is not the grant: the refused second use leaves the row granted"
    );
    assert_eq!(
        after_refusal_rows["requests"][1]["decision_reason"],
        json!("show this grant"),
        "a shown deny reason is not the grant: the refused second use keeps the decision reason"
    );
    assert_eq!(
        after_refusal_rows["requests"][1]["reason"],
        json!("show this step"),
        "a shown deny reason is not the grant: the refused second use keeps the request reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown deny reason is not the grant: the refused second use leaves the live list"
    );
}

#[cfg(test)]
#[test]
fn shown_stop_reason_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    fn capsule_state(stand_in: &StandIn, id: &str) -> Value {
        let listed = shell_capsules(stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id)
            .expect("the shell capsule list holds that id");
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let resource_a = "localhost://Public/plan-approval/a.txt";
    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });
    let shell_refusal: Result<Value, (u16, String)> =
        Err((403, "This endpoint requires shell privileges".to_owned()));

    let mut stand_in = StandIn::new();

    // A client stop never reaches the stop body, even before any session runs.
    let early_client = stop_shown_session(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "component-1",
        "granted",
    );
    assert_eq!(
        early_client, shell_refusal,
        "a shown stop reason is not the grant: a client stop is the shell-only refusal"
    );
    assert_ne!(
        early_client,
        Err((400, "stop needs a reason".to_owned())),
        "a shown stop reason is not the grant: the client refusal does not read the stop reason"
    );
    assert_ne!(
        early_client,
        Err((400, "unknown instance: component-1".to_owned())),
        "a shown stop reason is not the grant: the client refusal does not read the instance"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown stop reason is not the grant: a refused client stop stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown stop reason is not the grant: a refused client stop stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown stop reason is not the grant: a refused client stop mints no grant"
    );

    // An empty reason is refused before the instance is read.
    let empty_absent = stop_shown_session(&mut stand_in, Caller::Shell, "component-absent", "");
    assert_eq!(
        empty_absent,
        Err((400, "stop needs a reason".to_owned())),
        "a shown stop reason is not the grant: an empty reason is the route's reason refusal"
    );
    assert_ne!(
        empty_absent,
        Err((400, "unknown instance: component-absent".to_owned())),
        "a shown stop reason is not the grant: the empty-reason refusal runs before the instance lookup"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown stop reason is not the grant: the empty-reason refusal stores no capsule"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown stop reason is not the grant: the empty-reason refusal mints no grant"
    );

    // Two sessions run, and the first posts the plans the owner will see.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown stop reason is not the grant: the fresh stand-in names the first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "a shown stop reason is not the grant: the second running session is component-2"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown stop reason is not the grant: each launched session runs with no cause"
        );
    }

    // A client stop with an empty reason is still the shell refusal.
    let empty_client = stop_shown_session(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "component-1",
        "",
    );
    assert_eq!(
        empty_client, shell_refusal,
        "a shown stop reason is not the grant: a client stop with an empty reason is the shell-only refusal"
    );
    assert_ne!(
        empty_client,
        Err((400, "stop needs a reason".to_owned())),
        "a shown stop reason is not the grant: the client refusal is not the empty-reason refusal"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown stop reason is not the grant: the refused client stop leaves each session running with no cause"
        );
    }

    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown stop reason is not the grant: the first stored request is request-1"
    );
    assert_eq!(
        plan_a.len(),
        64,
        "a shown stop reason is not the grant: the hash of plan A has length 64"
    );

    // A shell stop with an empty reason stores nothing.
    assert_eq!(
        stop_shown_session(&mut stand_in, Caller::Shell, "component-1", ""),
        Err((400, "stop needs a reason".to_owned())),
        "a shown stop reason is not the grant: a shell stop with an empty reason is refused"
    );
    let pending_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_a,
    });
    let one_pending = json!({ "requests": [pending_a.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        one_pending,
        "a shown stop reason is not the grant: the empty-reason stop leaves the step pending"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown stop reason is not the grant: the empty-reason stop leaves each session running with no cause"
        );
    }
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown stop reason is not the grant: the empty-reason stop mints no grant"
    );

    // The owner grants the first step once and the second session's write once.
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-1",
            "once",
            &plan_a,
            "show this grant"
        ),
        Ok(json!({ "success": true })),
        "a shown stop reason is not the grant: the shell approval of the first step succeeds"
    );
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_B,
        resource_a,
        "read",
        "approved",
    )
    .expect("the agent's request route stores the second pending request");
    assert_eq!(
        second_step, "request-2",
        "a shown stop reason is not the grant: the second stored request is request-2"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown stop reason is not the grant: the hash of plan B has length 64"
    );
    let third_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_A,
        resource_a,
        "write",
        "",
    )
    .expect("the agent's request route stores the empty-reason request");
    assert_eq!(
        third_step, "request-3",
        "a shown stop reason is not the grant: the third stored request is request-3"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-3",
            "once",
            &plan_a,
            "keep the other"
        ),
        Ok(json!({ "success": true })),
        "a shown stop reason is not the grant: the shell approval of the other session's write succeeds"
    );
    let fourth_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_B,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores the fourth pending request");
    assert_eq!(
        fourth_step, "request-4",
        "a shown stop reason is not the grant: the fourth stored request is request-4"
    );

    let shell_entry_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let shell_entry_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "duration": "once",
        "granted_at": 0,
    });
    let two_shell_grants = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_a.clone(), shell_entry_c.clone()],
    });
    let two_live = shell_live(&stand_in);
    assert_eq!(
        two_live, two_shell_grants,
        "a shown stop reason is not the grant: the two granted steps are the live list"
    );
    for index in 0..2 {
        assert!(
            two_live["capabilities"][index].get("reason").is_none(),
            "a shown stop reason is not the grant: the live entry has no reason key"
        );
        assert!(
            two_live["capabilities"][index].get("rationale").is_none(),
            "a shown stop reason is not the grant: the live entry has no rationale key"
        );
    }

    // A client stop of either session is the shell refusal and changes nothing.
    let cancel_client = stop_shown_session(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "component-1",
        "cancel this session",
    );
    assert_eq!(
        cancel_client, shell_refusal,
        "a shown stop reason is not the grant: the asking session's stop is the shell-only refusal"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown stop reason is not the grant: the refused client stop leaves each session running"
        );
    }
    let granted_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "granted",
        "decision_reason": "show this grant",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let granted_and_pending_a = json!({ "requests": [granted_a.clone(), pending_b.clone()] });
    let rows_a = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        rows_a, granted_and_pending_a,
        "a shown stop reason is not the grant: the refused client stop leaves the granted step and the sibling pending"
    );
    assert_eq!(
        rows_a["requests"][1]["reason"],
        json!("approved"),
        "a shown stop reason is not the grant: the pending step keeps its own reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        two_shell_grants,
        "a shown stop reason is not the grant: the refused client stop leaves both live grants"
    );

    // An unknown instance with a stated reason is refused by that id.
    let cancel_absent = stop_shown_session(
        &mut stand_in,
        Caller::Shell,
        "component-absent",
        "cancel this session",
    );
    assert_eq!(
        cancel_absent,
        Err((400, "unknown instance: component-absent".to_owned())),
        "a shown stop reason is not the grant: the shell stop of an absent id is refused by that id"
    );
    assert_ne!(
        cancel_absent,
        Err((400, "stop needs a reason".to_owned())),
        "a shown stop reason is not the grant: the absent-id refusal is not the empty-reason refusal"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown stop reason is not the grant: the absent-id stop leaves each session running"
        );
    }
    assert_eq!(
        shell_live(&stand_in),
        two_shell_grants,
        "a shown stop reason is not the grant: the absent-id stop leaves both live grants"
    );

    // The owner's stated cancel reason stops the first session and is the settlement.
    assert_eq!(
        stop_shown_session(
            &mut stand_in,
            Caller::Shell,
            "component-1",
            "cancel this session"
        ),
        Ok(Value::Null),
        "a shown stop reason is not the grant: the shell stop reports its settlement"
    );
    let stopped_a = capsule_state(&stand_in, "component-1");
    assert_eq!(
        stopped_a,
        json!({ "id": "component-1", "status": "stopped", "cause": "stopped: cancel this session" }),
        "a shown stop reason is not the grant: the stated cancel reason is the capsule cause"
    );
    assert_ne!(
        stopped_a,
        json!({ "id": "component-1", "status": "stopped", "cause": "stopped: stop the shown session" }),
        "a shown stop reason is not the grant: the cause is not an earlier default"
    );
    assert_ne!(
        stopped_a,
        json!({ "id": "component-1", "status": "stopped", "cause": "stopped: granted" }),
        "a shown stop reason is not the grant: the cause is not a grant word"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-2"),
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "a shown stop reason is not the grant: the other session stays running with no cause"
    );

    let denied_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "denied",
        "decision_reason": "stopped: cancel this session",
        "settled_by": "runtime",
        "plan": plan_b,
    });
    let settled_a = json!({ "requests": [granted_a.clone(), denied_b.clone()] });
    let rows_after_stop = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        rows_after_stop, settled_a,
        "a shown stop reason is not the grant: the stated reason settles the pending step and keeps the granted step"
    );
    assert_eq!(
        rows_after_stop["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown stop reason is not the grant: the granted step keeps its approval rationale"
    );
    assert_eq!(
        rows_after_stop["requests"][1]["settled_by"],
        json!("runtime"),
        "a shown stop reason is not the grant: the runtime settles the pending step"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "stopped: cancel this session" })),
        "a shown stop reason is not the grant: the denied status body carries the stop cause"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown stop reason is not the grant: the stopped pending step is not a grant"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "approved" })),
        "a shown stop reason is not the grant: the status reason is the stop cause, not the request reason"
    );

    let granted_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "granted",
        "decision_reason": "keep the other",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    let rows_b = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        rows_b,
        json!({ "requests": [granted_c.clone(), pending_d.clone()] }),
        "a shown stop reason is not the grant: the other session's granted and pending steps stay"
    );

    let one_shell_grant = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_c.clone()],
    });
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown stop reason is not the grant: the stop revokes only the stopped session's live grant"
    );

    let revoked_a = execute(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        PLAN_A,
    );
    assert_eq!(
        revoked_a,
        Err((400, "grant is not live: Revoked".to_owned())),
        "a shown stop reason is not the grant: the stopped session's once grant is revoked"
    );
    assert_ne!(
        revoked_a,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown stop reason is not the grant: the refused use is not an exhausted grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown stop reason is not the grant: the refused use leaves the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown stop reason is not the grant: the refused use keeps the approval rationale"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown stop reason is not the grant: the refused use leaves the other session's live grant"
    );

    // A later reason on the stopped session is the not-live refusal, not a second stop.
    assert_eq!(
        stop_shown_session(&mut stand_in, Caller::Shell, "component-1", "granted"),
        Err((400, "instance is not live: stopped".to_owned())),
        "a shown stop reason is not the grant: a second stop of the stopped session is refused"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-1"),
        json!({ "id": "component-1", "status": "stopped", "cause": "stopped: cancel this session" }),
        "a shown stop reason is not the grant: the refused second stop keeps the first cause"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown stop reason is not the grant: the refused second stop keeps the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][1]["decision_reason"],
        json!("stopped: cancel this session"),
        "a shown stop reason is not the grant: the refused second stop keeps the stop cause"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][1]["status"],
        json!("denied"),
        "a shown stop reason is not the grant: the refused second stop leaves the step denied"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2"))["requests"][1],
        pending_d,
        "a shown stop reason is not the grant: the other session's pending step keeps its empty decision reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown stop reason is not the grant: the refused second stop leaves the live grant"
    );

    // A grant word is text on the running session's stop, not a grant.
    assert_eq!(
        stop_shown_session(&mut stand_in, Caller::Shell, "component-2", "granted"),
        Ok(Value::Null),
        "a shown stop reason is not the grant: the shell stop with reason granted reports its settlement"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-2"),
        json!({ "id": "component-2", "status": "stopped", "cause": "stopped: granted" }),
        "a shown stop reason is not the grant: the grant word is stored as the capsule cause"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-1"),
        json!({ "id": "component-1", "status": "stopped", "cause": "stopped: cancel this session" }),
        "a shown stop reason is not the grant: the first session keeps its own cause"
    );

    let denied_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "denied",
        "decision_reason": "stopped: granted",
        "settled_by": "runtime",
        "plan": plan_b,
    });
    let settled_b = json!({ "requests": [granted_c.clone(), denied_d.clone()] });
    let rows_after_second_stop = shell_requests(&stand_in, Some("component-2"));
    assert_eq!(
        rows_after_second_stop, settled_b,
        "a shown stop reason is not the grant: the grant-word stop settles the pending step and keeps the granted step"
    );
    assert_eq!(
        rows_after_second_stop["requests"][0]["decision_reason"],
        json!("keep the other"),
        "a shown stop reason is not the grant: the other session's granted step keeps its rationale"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "denied", "reason": "stopped: granted" })),
        "a shown stop reason is not the grant: the second denied status body carries the stop cause"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown stop reason is not the grant: the stop cause is not a granted status"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "denied", "reason": "show this step" })),
        "a shown stop reason is not the grant: the status reason is the stop cause, not the request reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown stop reason is not the grant: the second stop revokes the last live grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown stop reason is not the grant: the first session's two rows stay"
    );

    let revoked_c = execute(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        "request-3",
        PLAN_A,
    );
    assert_eq!(
        revoked_c,
        Err((400, "grant is not live: Revoked".to_owned())),
        "a shown stop reason is not the grant: the second stopped session's once grant is revoked"
    );
    assert_ne!(
        revoked_c,
        Ok(json!({ "valid": true })),
        "a shown stop reason is not the grant: the grant-word stop mints no use"
    );
    assert_ne!(
        revoked_c,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown stop reason is not the grant: the refused use is not an exhausted grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        settled_b,
        "a shown stop reason is not the grant: the refused use leaves the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2"))["requests"][0]["decision_reason"],
        json!("keep the other"),
        "a shown stop reason is not the grant: the refused use keeps the other rationale"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown stop reason is not the grant: the refused use leaves the empty live list"
    );
}

#[cfg(test)]
#[test]
fn shown_worker_exit_is_not_the_grant() {
    use agent_conformance::standin_runtime::{Caller, StandIn};
    use fixtures::{PLAN_A, PLAN_B};
    use journeys::{request, running_agent};
    use serde_json::{json, Value};

    fn shell_requests(stand_in: &StandIn, session: Option<&str>) -> Value {
        read_shown_requests(stand_in, Caller::Shell, session)
            .expect("the shell reads a session's request list")
    }

    fn shell_live(stand_in: &StandIn) -> Value {
        read_shown_grants(stand_in, Caller::Shell, None).expect("the shell reads the live list")
    }

    fn shell_capsules(stand_in: &StandIn) -> Vec<Value> {
        stand_in
            .get_capsules(Caller::Shell)
            .expect("shell capsules")["capsules"]
            .as_array()
            .cloned()
            .expect("the shell capsule list holds a capsules array")
    }

    fn capsule_state(stand_in: &StandIn, id: &str) -> Value {
        let listed = shell_capsules(stand_in)
            .into_iter()
            .find(|entry| entry["id"] == id)
            .expect("the shell capsule list holds that id");
        json!({ "id": listed["id"], "status": listed["status"], "cause": listed["cause"] })
    }

    let plan_a = plan_sha256(PLAN_A);
    let plan_b = plan_sha256(PLAN_B);
    let resource_a = "localhost://Public/plan-approval/a.txt";
    let empty_requests: Value = json!({ "requests": [] });
    let empty_shell: Value = json!({ "scope": "all_sessions_live", "capabilities": [] });

    let mut stand_in = StandIn::new();

    // No instance is live yet: the reap is refused by the id and stores nothing.
    let absent_before = shown_worker_exited(&mut stand_in, "component-1");
    assert_eq!(
        absent_before,
        Err((400, "unknown instance: component-1".to_owned())),
        "a shown worker exit is not the grant: a reap before any launch is refused by that id"
    );
    assert_ne!(
        absent_before,
        Err((400, "instance is not live: failed".to_owned())),
        "a shown worker exit is not the grant: the unknown-id refusal is not the not-live refusal"
    );
    assert_eq!(
        shell_capsules(&stand_in),
        Vec::<Value>::new(),
        "a shown worker exit is not the grant: a refused early reap stores no capsule"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        empty_requests,
        "a shown worker exit is not the grant: a refused early reap stores no request"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown worker exit is not the grant: a refused early reap mints no grant"
    );

    // Two sessions run, and both keep no cause.
    let first = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    let second = running_agent(&mut stand_in, Caller::Shell)
        .expect("the shell launches one running session");
    assert_eq!(
        first, "component-1",
        "a shown worker exit is not the grant: the fresh stand-in names the first session component-1"
    );
    assert_eq!(
        second, "component-2",
        "a shown worker exit is not the grant: the second running session is component-2"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown worker exit is not the grant: each launched session runs with no cause"
        );
    }

    // A reap of an absent id is refused by that id and leaves both sessions.
    let absent_live = shown_worker_exited(&mut stand_in, "component-absent");
    assert_eq!(
        absent_live,
        Err((400, "unknown instance: component-absent".to_owned())),
        "a shown worker exit is not the grant: a reap of an absent id is refused by that id"
    );
    assert_ne!(
        absent_live,
        Err((400, "instance is not live: failed".to_owned())),
        "a shown worker exit is not the grant: the absent-id refusal is not the not-live refusal"
    );
    for id in [&first, &second] {
        assert_eq!(
            capsule_state(&stand_in, id),
            json!({ "id": id, "status": "running", "cause": "" }),
            "a shown worker exit is not the grant: the absent-id reap leaves each session running"
        );
    }
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown worker exit is not the grant: the absent-id reap mints no grant"
    );

    // The first session submits two steps and the owner grants the first once.
    let first_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores one pending request");
    assert_eq!(
        first_step, "request-1",
        "a shown worker exit is not the grant: the first stored request is request-1"
    );
    assert_eq!(
        plan_a.len(),
        64,
        "a shown worker exit is not the grant: the hash of plan A has length 64"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-1",
            "once",
            &plan_a,
            "show this grant"
        ),
        Ok(json!({ "success": true })),
        "a shown worker exit is not the grant: the shell approval of the first step succeeds"
    );
    let second_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_B,
        resource_a,
        "read",
        "approved",
    )
    .expect("the agent's request route stores the second pending request");
    assert_eq!(
        second_step, "request-2",
        "a shown worker exit is not the grant: the second stored request is request-2"
    );
    assert_eq!(
        plan_b.len(),
        64,
        "a shown worker exit is not the grant: the hash of plan B has length 64"
    );

    // The other session submits a write and a read; the owner grants the write once.
    let third_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_A,
        resource_a,
        "write",
        "",
    )
    .expect("the agent's request route stores the empty-reason request");
    assert_eq!(
        third_step, "request-3",
        "a shown worker exit is not the grant: the third stored request is request-3"
    );
    assert_eq!(
        approve(
            &mut stand_in,
            Caller::Shell,
            "request-3",
            "once",
            &plan_a,
            "keep the other"
        ),
        Ok(json!({ "success": true })),
        "a shown worker exit is not the grant: the shell approval of the other session's write succeeds"
    );
    let fourth_step = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        PLAN_B,
        resource_a,
        "read",
        "show this step",
    )
    .expect("the agent's request route stores the fourth pending request");
    assert_eq!(
        fourth_step, "request-4",
        "a shown worker exit is not the grant: the fourth stored request is request-4"
    );

    let shell_entry_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "duration": "once",
        "granted_at": 0,
    });
    let shell_entry_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "duration": "once",
        "granted_at": 0,
    });
    let two_shell_grants = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_a.clone(), shell_entry_c.clone()],
    });
    let two_live = shell_live(&stand_in);
    assert_eq!(
        two_live, two_shell_grants,
        "a shown worker exit is not the grant: the two granted steps are the live list"
    );
    for index in 0..2 {
        assert!(
            two_live["capabilities"][index].get("reason").is_none(),
            "a shown worker exit is not the grant: the live entry has no reason key"
        );
        assert!(
            two_live["capabilities"][index].get("rationale").is_none(),
            "a shown worker exit is not the grant: the live entry has no rationale key"
        );
    }

    // The Runtime reaps the first session with its own fixed cause.
    assert_eq!(
        shown_worker_exited(&mut stand_in, "component-1"),
        Ok(()),
        "a shown worker exit is not the grant: the reap reports its settlement"
    );
    let failed_a = capsule_state(&stand_in, "component-1");
    assert_eq!(
        failed_a,
        json!({ "id": "component-1", "status": "failed", "cause": "worker exited" }),
        "a shown worker exit is not the grant: the reap stores the fixed cause as the capsule cause"
    );
    assert_ne!(
        failed_a,
        json!({ "id": "component-1", "status": "failed", "cause": "stopped: worker exited" }),
        "a shown worker exit is not the grant: the fixed cause is not a stop cause"
    );
    assert_ne!(
        failed_a,
        json!({ "id": "component-1", "status": "failed", "cause": "granted" }),
        "a shown worker exit is not the grant: the fixed cause is not a grant word"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-2"),
        json!({ "id": "component-2", "status": "running", "cause": "" }),
        "a shown worker exit is not the grant: the other session stays running with no cause"
    );

    let granted_a = json!({
        "request_id": "request-1",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "granted",
        "decision_reason": "show this grant",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let denied_b = json!({
        "request_id": "request-2",
        "session_id": "component-1",
        "resource": resource_a,
        "action": "read",
        "reason": "approved",
        "status": "denied",
        "decision_reason": "worker exited",
        "settled_by": "runtime",
        "plan": plan_b,
    });
    let settled_a = json!({ "requests": [granted_a.clone(), denied_b.clone()] });
    let rows_after_reap = shell_requests(&stand_in, Some("component-1"));
    assert_eq!(
        rows_after_reap, settled_a,
        "a shown worker exit is not the grant: the reap denies the pending step and keeps the granted step"
    );
    assert_eq!(
        rows_after_reap["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown worker exit is not the grant: the granted step keeps its approval rationale"
    );
    assert_eq!(
        rows_after_reap["requests"][1]["settled_by"],
        json!("runtime"),
        "a shown worker exit is not the grant: the runtime settles the pending step"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "worker exited" })),
        "a shown worker exit is not the grant: the denied status body carries the fixed cause"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown worker exit is not the grant: the denied pending step is not a grant"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            "request-2",
        ),
        Ok(json!({ "status": "denied", "reason": "approved" })),
        "a shown worker exit is not the grant: the status reason is the fixed cause, not the request reason"
    );
    let granted_read = read_shown_request(
        &stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
    )
    .expect("the owning session reads its granted step");
    assert_eq!(
        granted_read,
        json!({ "status": "granted" }),
        "a shown worker exit is not the grant: the granted status body is the status word alone"
    );
    assert!(
        granted_read.get("reason").is_none(),
        "a shown worker exit is not the grant: the granted status body has no reason key"
    );

    let granted_c = json!({
        "request_id": "request-3",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "write",
        "reason": "",
        "status": "granted",
        "decision_reason": "keep the other",
        "settled_by": "shell",
        "plan": plan_a,
    });
    let pending_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "pending",
        "decision_reason": "",
        "settled_by": null,
        "plan": plan_b,
    });
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        json!({ "requests": [granted_c.clone(), pending_d.clone()] }),
        "a shown worker exit is not the grant: the other session's granted and pending steps stay"
    );

    let one_shell_grant = json!({
        "scope": "all_sessions_live",
        "capabilities": [shell_entry_c.clone()],
    });
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown worker exit is not the grant: the reap revokes only the reaped session's live grant"
    );
    assert_eq!(
        read_shown_grants(
            &stand_in,
            Caller::Client {
                session_id: "component-1",
            },
            None,
        ),
        Ok(json!({ "capabilities": [] })),
        "a shown worker exit is not the grant: the reaped session's live list is empty"
    );

    let revoked_a = execute(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        "request-1",
        PLAN_A,
    );
    assert_eq!(
        revoked_a,
        Err((400, "grant is not live: Revoked".to_owned())),
        "a shown worker exit is not the grant: the reaped session's once grant is revoked"
    );
    assert_ne!(
        revoked_a,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown worker exit is not the grant: the refused use is not an exhausted grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown worker exit is not the grant: the refused use leaves the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0]["decision_reason"],
        json!("show this grant"),
        "a shown worker exit is not the grant: the refused use keeps the approval rationale"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown worker exit is not the grant: the refused use leaves the other session's live grant"
    );

    // A second reap of the failed session is the not-live refusal, not a second settlement.
    assert_eq!(
        shown_worker_exited(&mut stand_in, "component-1"),
        Err((400, "instance is not live: failed".to_owned())),
        "a shown worker exit is not the grant: a second reap of the failed session is refused"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-1"),
        json!({ "id": "component-1", "status": "failed", "cause": "worker exited" }),
        "a shown worker exit is not the grant: the refused second reap keeps the first cause"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][0],
        granted_a,
        "a shown worker exit is not the grant: the refused second reap keeps the granted step"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][1],
        denied_b,
        "a shown worker exit is not the grant: the refused second reap keeps the denied step"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1"))["requests"][1]["decision_reason"],
        json!("worker exited"),
        "a shown worker exit is not the grant: the refused second reap keeps the fixed cause"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2"))["requests"][1],
        pending_d,
        "a shown worker exit is not the grant: the other session's pending step keeps its empty decision reason"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2"))["requests"][1]["decision_reason"],
        json!(""),
        "a shown worker exit is not the grant: the refused second reap leaves the other pending step empty"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown worker exit is not the grant: the refused second reap leaves the live grant"
    );

    // A later stop with a grant word is that same refusal and stores nothing.
    assert_eq!(
        stop_shown_session(&mut stand_in, Caller::Shell, "component-1", "granted"),
        Err((400, "instance is not live: failed".to_owned())),
        "a shown worker exit is not the grant: a later shell stop of the failed session is refused"
    );
    let stopped_a = capsule_state(&stand_in, "component-1");
    assert_eq!(
        stopped_a,
        json!({ "id": "component-1", "status": "failed", "cause": "worker exited" }),
        "a shown worker exit is not the grant: the refused stop keeps the fixed cause"
    );
    assert_ne!(
        stopped_a,
        json!({ "id": "component-1", "status": "failed", "cause": "stopped: granted" }),
        "a shown worker exit is not the grant: the refused stop does not store a stop cause"
    );
    assert_eq!(
        shell_live(&stand_in),
        one_shell_grant,
        "a shown worker exit is not the grant: the refused stop leaves the live grant"
    );

    // A later submit on the failed session is the not-live refusal and stores nothing.
    let late_submit = request(
        &mut stand_in,
        Caller::Client {
            session_id: "component-1",
        },
        PLAN_A,
        resource_a,
        "read",
        "granted",
    );
    assert_eq!(
        late_submit,
        Err((400, "instance is not live: failed".to_owned())),
        "a shown worker exit is not the grant: a later submit on the failed session is refused"
    );
    assert_ne!(
        late_submit,
        Err((400, "unknown instance: component-1".to_owned())),
        "a shown worker exit is not the grant: the later submit is the not-live refusal, not the unknown-id refusal"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown worker exit is not the grant: the refused submit leaves the two rows"
    );

    // The Runtime reaps the other session too.
    assert_eq!(
        shown_worker_exited(&mut stand_in, "component-2"),
        Ok(()),
        "a shown worker exit is not the grant: the second reap reports its settlement"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-2"),
        json!({ "id": "component-2", "status": "failed", "cause": "worker exited" }),
        "a shown worker exit is not the grant: the second reap stores the fixed cause"
    );
    assert_eq!(
        capsule_state(&stand_in, "component-1"),
        json!({ "id": "component-1", "status": "failed", "cause": "worker exited" }),
        "a shown worker exit is not the grant: the first session keeps its own fixed cause"
    );

    let denied_d = json!({
        "request_id": "request-4",
        "session_id": "component-2",
        "resource": resource_a,
        "action": "read",
        "reason": "show this step",
        "status": "denied",
        "decision_reason": "worker exited",
        "settled_by": "runtime",
        "plan": plan_b,
    });
    let settled_b = json!({ "requests": [granted_c.clone(), denied_d.clone()] });
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        settled_b,
        "a shown worker exit is not the grant: the second reap denies the pending step and keeps the granted step"
    );
    assert_eq!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "denied", "reason": "worker exited" })),
        "a shown worker exit is not the grant: the second denied status body carries the fixed cause"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "granted" })),
        "a shown worker exit is not the grant: the second denied pending step is not a grant"
    );
    assert_ne!(
        read_shown_request(
            &stand_in,
            Caller::Client {
                session_id: "component-2",
            },
            "request-4",
        ),
        Ok(json!({ "status": "denied", "reason": "show this step" })),
        "a shown worker exit is not the grant: the second status reason is the fixed cause, not the request reason"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown worker exit is not the grant: the second reap revokes the last live grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-1")),
        settled_a,
        "a shown worker exit is not the grant: the first session's two rows stay"
    );

    let revoked_c = execute(
        &mut stand_in,
        Caller::Client {
            session_id: "component-2",
        },
        "request-3",
        PLAN_A,
    );
    assert_eq!(
        revoked_c,
        Err((400, "grant is not live: Revoked".to_owned())),
        "a shown worker exit is not the grant: the second reaped session's once grant is revoked"
    );
    assert_ne!(
        revoked_c,
        Ok(json!({ "valid": true })),
        "a shown worker exit is not the grant: the fixed cause mints no use"
    );
    assert_ne!(
        revoked_c,
        Err((400, "grant is not live: Exhausted".to_owned())),
        "a shown worker exit is not the grant: the refused use is not an exhausted grant"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2")),
        settled_b,
        "a shown worker exit is not the grant: the refused use leaves the two rows"
    );
    assert_eq!(
        shell_requests(&stand_in, Some("component-2"))["requests"][0]["decision_reason"],
        json!("keep the other"),
        "a shown worker exit is not the grant: the refused use keeps the other rationale"
    );
    assert_eq!(
        shell_live(&stand_in),
        empty_shell,
        "a shown worker exit is not the grant: the refused use leaves the empty live list"
    );
}
