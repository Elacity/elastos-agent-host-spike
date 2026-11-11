//! Row 6, presence. Entries: `request_community_presence`
//! (gateway_collaboration_presence.rs:310) and `community_presence_state`
//! (line 299), called by `chat_room_community_presence_request` and Chat;
//! plus the stored-file functions they reach, `presence_grant::state` and
//! `open_request_at`.

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
    // The request first reads the Profile on the child and finds none.
    let asked = request_community_presence(&state, &person.ctx, true);
    assert_eq!(
        refusal(asked).as_deref(),
        Some("Create your Profile before choosing how Community shows you.")
    );
    assert_eq!(community_presence_state(&state, &person.ctx), None);
    // Behind the Profile read, the grant file looks the person's root up in
    // the child's own auth state (collaboration_presence_grant.rs:233).
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
