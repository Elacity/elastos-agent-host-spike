//! Row 5, contacts. Entries: `load_configured_contact_authority_for_context`
//! (gateway_home_system.rs:1183), which every People contact route calls
//! first, and one of those routes, `people_contact_request_create`
//! (line 789).

use super::*;
use crate::api::gateway::gateway_home_system::{
    people_contact_request_create, PeopleContactRequestCreate,
};

#[tokio::test(flavor = "current_thread")]
async fn r8d_child_contacts_are_refused_at_the_profile_gate() {
    let person = passkey_person(PEOPLE_CAPSULE_ID);
    let child = person.child.path();
    let service = discovery_service(child).await;
    // No Profile is read on the child, so the function builds no contact
    // authority and the contact store is never opened.
    let authority =
        load_configured_contact_authority_for_context(child, &person.ctx, Some(&service)).unwrap();
    assert!(authority.is_none(), "the child builds no contact authority");
    // The route itself, with a token the child's own key signed (see
    // `route_headers`). It answers the missing authority with its own words.
    let mut state = person.child_state();
    state.collaboration_discovery_service = Some(service.clone());
    let body: PeopleContactRequestCreate =
        serde_json::from_value(json!({"profile_id": "r8d-not-reached"})).unwrap();
    let answer = people_contact_request_create(
        axum::extract::State(state),
        person.route_headers(PEOPLE_CAPSULE_ID),
        axum::Json(body),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&body),
        "Save your Profile before using People contacts"
    );
    // The same function on the parent's data directory, same context, still
    // with the service built on the child's device key. It shows only where
    // the Profile is looked up; it is not how a parent is configured.
    let on_parent = load_configured_contact_authority_for_context(
        person.parent.path(),
        &person.ctx,
        Some(&service),
    )
    .unwrap();
    assert!(
        on_parent.is_some(),
        "the parent's directory holds a Profile"
    );
    person.assert_child_holds_only(&[]);
}
