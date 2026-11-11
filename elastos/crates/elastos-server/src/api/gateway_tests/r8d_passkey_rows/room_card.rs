//! Row 7, room card and trusted authority. Entries:
//! `home_room_profile_card_projection_for_context`
//! (gateway_home_system.rs:6545) and `trusted_chat_room_profile_authority`
//! (gateway_room.rs:1361), which the Chat room session routes call.

use super::*;

#[test]
fn r8d_child_room_card_and_authority_read_the_passkey_persons_profile() {
    let person = passkey_person(CHAT_ROOM_CAPSULE_ID);
    let child = person.child.path();
    let card = home_room_profile_card_projection_for_context(child, &person.ctx).unwrap();
    assert!(card.is_none(), "the child builds no card");
    let trusted = trusted_chat_room_profile_authority(child, &person.ctx);
    assert_eq!(
        refusal(trusted).as_deref(),
        Some("signed Profile is unavailable")
    );
    // The same two calls on the parent's data directory, same context.
    let parent = person.parent.path();
    let card = home_room_profile_card_projection_for_context(parent, &person.ctx).unwrap();
    let name = card.map(|card| card.display_name);
    assert_eq!(name.as_deref(), Some("Parent Person"));
    assert!(trusted_chat_room_profile_authority(parent, &person.ctx).is_ok());
    person.assert_child_holds_only(&[]);
}
