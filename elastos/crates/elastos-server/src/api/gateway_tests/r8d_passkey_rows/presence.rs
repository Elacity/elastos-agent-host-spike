//! Row 6, presence. Entries: `request_community_presence`
//! (gateway_collaboration_presence.rs:310) and `community_presence_state`
//! (line 299), called by `chat_room_community_presence_request` and Chat.
//! For this person both stop where they read the Profile (line 287) and
//! reach no grant-file function. The row then calls two grant-file functions
//! directly: `presence_grant::state`, which `community_presence_state` calls
//! once a Profile is read (line 304), and `open_request_at`, which the
//! answer and Inbox-card functions call (lines 436 and 477).

use super::*;
use crate::collaboration_presence_grant as grant;

fn presence_state(person: &PasskeyPerson) -> GatewayState {
    let dir = person.child.path();
    let chat = crate::collaboration_product::test_chat_product_port(dir, "r8d", "community");
    let presence = crate::collaboration_presence::CollaborationPresenceProductPort::new(
        chat.test_core().clone(),
    )
    .unwrap()
    .with_presence_authority(grant::test_authority());
    let mut state = person.child_state();
    state.collaboration_chat_product_port = Some(chat);
    state.collaboration_presence_product_port = Some(presence);
    state
}

#[tokio::test(flavor = "current_thread")]
async fn r8d_child_presence_request_and_grant_are_refused_for_the_passkey_person() {
    let person = passkey_person(CHAT_ROOM_CAPSULE_ID);
    let child = person.child.path();
    let state = presence_state(&person);
    // Building the test Community port wrote nothing into the child.
    person.assert_child_holds_only(&[]);
    // The request reads the Profile on the child, finds none and stops.
    let asked = request_community_presence(&state, &person.ctx, true);
    assert_eq!(
        refusal(asked).as_deref(),
        Some("Create your Profile before choosing how Community shows you.")
    );
    // The state read stops at the same place and hides the reason.
    assert_eq!(community_presence_state(&state, &person.ctx), None);
    // Called directly, not through the two functions above: each grant-file
    // function looks the person's root up in the child's own auth state
    // (collaboration_presence_grant.rs:233).
    let scope = state
        .collaboration_presence_product_port
        .as_ref()
        .unwrap()
        .presence_scope();
    let read = grant::state(child, PERSON, &scope);
    assert_eq!(refusal(read).as_deref(), Some(NO_STORED_RECORD));
    let open = grant::open_request_at(child, PERSON, &scope);
    assert_eq!(refusal(open).as_deref(), Some(NO_STORED_RECORD));
    person.assert_child_holds_only(&[]);
}
