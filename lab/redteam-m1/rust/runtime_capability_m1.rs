//! M1 red team: the Runtime capability handlers behind A6's observation.
//!
//! `test_m1_runtime.py` copies this file into a scratch clone as
//! `elastos/crates/elastos-server/src/api/handlers/redteam_m1_capability.rs` and
//! declares it from that clone's `capability.rs` as a test-only child module.
//! No Runtime source in this repository changes.
//!
//! A6's rows (`two_instances_overlap_with_separate_grants`,
//! `instance_grant_does_not_authorise_sibling`) read "the sibling's read
//! reaches a new pending request in its original session" as evidence that one
//! instance's grant does not authorise its sibling. These tests ask whether
//! that observation can tell a scoped grant from any other request.

use super::*;
use elastos_runtime::capability::CapabilityToken;

const OWN: &str = "localhost://Public/agent-conformance-grants/instance-1/own.txt";

fn state() -> CapabilityState {
    let audit_log = Arc::new(elastos_runtime::primitives::audit::AuditLog::new());
    let store = Arc::new(elastos_runtime::capability::CapabilityStore::new());
    let metrics = Arc::new(elastos_runtime::primitives::metrics::MetricsManager::new());
    let capability_manager = Arc::new(CapabilityManager::new(store, audit_log.clone(), metrics));
    CapabilityState {
        pending_store: Arc::new(PendingRequestStore::new(audit_log.clone())),
        capability_manager,
        policy_evaluator: Arc::new(PolicyEvaluator::new(
            Box::new(elastos_runtime::capability::evaluator::ShellPassthroughVerifier),
            audit_log,
        )),
    }
}

async fn ask(state: &CapabilityState, session: &Session) -> RequestCapabilityOutput {
    request_capability(
        State(state.clone()),
        Extension(session.clone()),
        Json(RequestCapabilityInput {
            resource: OWN.to_string(),
            action: "read".to_string(),
            reason: "agent conformance: instance-1 own".to_string(),
        }),
    )
    .await
    .expect("a request returns a structured answer")
    .0
}

async fn grant_for_session(state: &CapabilityState, request_id: String) -> GrantRequestOutput {
    grant_request(
        State(state.clone()),
        Extension(Session::new_shell("shell".to_string())),
        Json(GrantRequestInput {
            request_id,
            duration: "session".to_string(),
            rationale: Some("red team".to_string()),
        }),
    )
    .await
    .expect("the shell grants the pending request")
    .0
}

/// Control, A6's own observation: with instance-1's session grant live, the
/// sibling session's request for the same resource reaches a new pending
/// request.
#[tokio::test]
async fn control_a_sibling_request_reaches_pending() {
    let state = state();
    let owner = Session::new_capsule("instance-1".to_string());
    let sibling = Session::new_capsule("instance-2".to_string());
    let first = ask(&state, &owner).await;
    assert_eq!(first.status, "pending");
    assert!(grant_for_session(&state, first.request_id.unwrap()).await.success);
    assert_eq!(ask(&state, &sibling).await.status, "pending");
}

/// Control: the Runtime check that does keep a grant to its session. The token
/// names the session as its capsule, and `validate` refuses another caller.
/// A6's journey never presents one instance's token from the other instance,
/// so this check is never exercised there.
#[tokio::test]
async fn control_a_token_is_refused_for_another_session() {
    let state = state();
    let owner = Session::new_capsule("instance-1".to_string());
    let sibling = Session::new_capsule("instance-2".to_string());
    let first = ask(&state, &owner).await;
    let granted = grant_for_session(&state, first.request_id.unwrap()).await;
    let token = CapabilityToken::from_base64(&granted.token.expect("a granted token")).unwrap();
    let resource = ResourceId::new(OWN);
    state
        .capability_manager
        .validate(&token, &owner.id.to_string(), Action::Read, &resource, None)
        .await
        .expect("the owner session may use its token");
    assert!(state
        .capability_manager
        .validate(&token, &sibling.id.to_string(), Action::Read, &resource, None)
        .await
        .is_err());
}

/// FM-A6. The owner session, holding a live session grant for the resource,
/// asks again and also reaches a new pending request. "Reaches a new pending
/// request" is therefore the Runtime's answer to every request
/// (`request_capability`: "For now, all requests go to pending"), and the
/// sibling observation cannot show that a grant stays with its session: the
/// fixture's denial is what refuses the sibling.
#[tokio::test]
async fn fm_a6_a_live_grant_changes_the_answer_for_its_own_session() {
    let state = state();
    let owner = Session::new_capsule("instance-1".to_string());
    let first = ask(&state, &owner).await;
    assert_eq!(first.status, "pending");
    assert!(grant_for_session(&state, first.request_id.unwrap()).await.success);
    let again = ask(&state, &owner).await;
    assert_ne!(
        again.status, "pending",
        "the owner's live session grant made no difference: every request reaches pending"
    );
}
