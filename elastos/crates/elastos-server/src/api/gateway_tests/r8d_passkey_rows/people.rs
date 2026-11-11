//! Row 5, contacts. Entry: `load_configured_contact_authority_for_context`
//! (gateway_home_system.rs:1183), which every People contact route calls
//! first, for example `people_contact_request_create` (line 789).

use super::*;

#[tokio::test]
async fn r8d_child_contacts_are_refused_at_the_profile_gate() {
    let person = passkey_person(PEOPLE_CAPSULE_ID);
    let child = person.child.path();
    let service = discovery_service(child).await;
    // No Profile is read on the child, so the function builds no contact
    // authority and the contact store is never opened.
    let authority =
        load_configured_contact_authority_for_context(child, &person.ctx, Some(&service)).unwrap();
    assert!(authority.is_none(), "the child builds no contact authority");
    // The route answers a missing authority with these two calls
    // (gateway_home_system.rs:815-819). Its message constant is private, so
    // the row hands the same words to them.
    let answer = room_service_error_response(profile_required_error(
        "Save your Profile before using People contacts",
    ));
    assert_eq!(answer.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&body),
        "Save your Profile before using People contacts"
    );
    // The same call on the parent's data directory, same context.
    let on_parent = load_configured_contact_authority_for_context(
        person.parent.path(),
        &person.ctx,
        Some(&service),
    )
    .unwrap();
    assert!(on_parent.is_some(), "the parent builds a contact authority");
    person.assert_child_holds_only(&[]);
}
