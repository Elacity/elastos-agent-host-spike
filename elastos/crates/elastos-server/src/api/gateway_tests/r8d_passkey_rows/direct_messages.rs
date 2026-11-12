//! Row 9, direct messages. Entry: the route `chat_direct_conversations`
//! (gateway_room.rs:300). Like the other two direct-message routes it starts
//! with `direct_authority` (line 271), which builds the contact authority for
//! the context and turns a missing one into an error (line 291).

use super::*;
use crate::api::gateway::gateway_room::{
    chat_direct_conversations, ChatDirectConversationReadOptions,
};

#[tokio::test(flavor = "current_thread")]
async fn r8d_child_direct_messages_are_refused_at_the_profile_gate() {
    let person = passkey_person(CHAT_ROOM_CAPSULE_ID);
    let child = person.child.path();
    let service = discovery_service(child).await;
    // The call `direct_authority` makes for its contact authority.
    let authority =
        load_configured_contact_authority_for_context(child, &person.ctx, Some(&service)).unwrap();
    assert!(authority.is_none(), "the child builds no direct authority");
    // The route itself, with a token the child's own key signed.
    // `route_headers` has already asserted that this token verifies to the
    // person's context, so the answer below is not the token refusal at
    // line 278, which uses the same words.
    let mut state = person.child_state();
    state.collaboration_discovery_service = Some(service);
    let answer = chat_direct_conversations(
        axum::extract::State(state),
        person.route_headers(CHAT_ROOM_CAPSULE_ID),
        axum::extract::Query(ChatDirectConversationReadOptions::default()),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::UNAUTHORIZED);
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body,
        json!({"error": "direct message authority is unavailable"})
    );
    // Reading conversations is refused here; register and send start with
    // the same `direct_authority` call and are not run.
    person.assert_child_holds_only(&[]);
}
