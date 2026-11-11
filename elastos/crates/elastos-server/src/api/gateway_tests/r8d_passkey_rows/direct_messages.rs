//! Row 9, direct messages. `direct_authority` (gateway_room.rs:271) builds
//! the contact authority for the context with
//! `load_configured_contact_authority_for_context` before any of the three
//! Chat direct-message routes registers, reads or sends.

use super::*;
use crate::collaboration_direct_messages::DirectApiError;

#[tokio::test]
async fn r8d_child_direct_messages_are_refused_at_the_profile_gate() {
    let person = passkey_person(CHAT_ROOM_CAPSULE_ID);
    let child = person.child.path();
    let service = discovery_service(child).await;
    let authority =
        load_configured_contact_authority_for_context(child, &person.ctx, Some(&service)).unwrap();
    assert!(authority.is_none(), "the child builds no direct authority");
    // `direct_authority` turns a missing authority into this error
    // (gateway_room.rs:291). Register, read and send are not reached.
    assert_eq!(
        DirectApiError::Authority.to_string(),
        "direct message authority is unavailable"
    );
    person.assert_child_holds_only(&[]);
}
