//! Family 6. `direct_authority` (gateway_room.rs:271) builds the contact
//! authority for the context; the three Chat direct-message routes then call
//! `conversation_summaries`, `message_summaries` and `send_text_authorized`
//! (lines 313, 359, 411). None of the three calls
//! `register_configured_contact_sync_for_context`. Its callers are
//! `home_launch` (gateway_home_runtime.rs:105), `people_contact_remove`
//! (gateway_home_system.rs:771), `send_profile_contact_request_response`
//! (line 900), `configured_people_discovery_action` (line 1318) and
//! `decide_contact_request` (gateway_inbox.rs:691). The rows call it
//! themselves, as `home_launch` does when Home opens.

use super::*;
use crate::collaboration_direct_messages::{DirectSendAuthority, DirectSendIntent};
use crate::collaboration_discovery_runtime::CollaborationDiscoveryService;

fn direct_authority_for(
    dir: &std::path::Path,
    ctx: &HomeLaunchTokenContext,
    service: &CollaborationDiscoveryService,
) -> anyhow::Result<ConfiguredContactAuthority> {
    load_configured_contact_authority_for_context(dir, ctx, Some(service))
        .and_then(|found| found.ok_or_else(|| anyhow::anyhow!("none: Profile required")))
}

/// Register and read: the steps both rows run. Returns the ids of the
/// conversations listed.
fn register_and_read(
    steps: &mut Steps,
    service: &CollaborationDiscoveryService,
    ctx: &HomeLaunchTokenContext,
    authority: &ConfiguredContactAuthority,
    now: u64,
) -> Option<Vec<String>> {
    let registered = register_configured_contact_sync_for_context(service, ctx, authority, now);
    steps.step("register the context for direct messages", registered);
    let listed = service
        .direct_message_service()
        .conversation_summaries(authority.store.as_ref())
        .map(|list| list.into_iter().map(|c| c.conversation_id).collect());
    steps.step("read conversations (conversation_summaries)", listed)
}

/// Send one message in `conversation` and read it back. Only the control
/// runs this: it has an accepted contact.
async fn send_and_read_back(
    steps: &mut Steps,
    service: &CollaborationDiscoveryService,
    ctx: &HomeLaunchTokenContext,
    authority: &ConfiguredContactAuthority,
    conversation: &str,
    now: u64,
) {
    let direct = service.direct_message_service();
    let sent = direct
        .send_text_authorized(
            DirectSendAuthority {
                contact_store: authority.store.clone(),
                profile: authority.profile.clone(),
                session_id: ctx.session_id(),
                proof_binding_id: ctx.proof_binding_id(),
                grant_id: ctx.grant_id(),
                authority_app: HOME_CAPSULE_ID,
            },
            DirectSendIntent {
                request_id: "r8c-send",
                conversation_id: conversation,
                text: "hello from r8c",
                retry_existing: false,
                now,
            },
        )
        .await;
    // The answer is a delivery status, settled or pending. The route reports
    // both as an accepted send (gateway_room.rs:430-437); which one it is
    // depends on the peer's timing, so the read below is the check.
    steps.step("send one message (send_text_authorized)", sent);
    let read = direct
        .message_summaries(
            authority.store.as_ref(),
            &authority.profile,
            conversation,
            now,
        )
        .map(|messages| messages.len());
    steps.check(
        "read messages returns the sent message",
        read == Ok(1),
        &read,
    );
}

/// Register and read. A send is not shown for this person: it needs an
/// accepted contact, and the test cannot arrange one because the contact
/// store refuses this person's writes (the contacts row prints that
/// refusal). The control runs the send.
#[tokio::test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
async fn r8c_child_direct_messages_register_and_read_under_the_parent_root() {
    let child = child(CHAT_ROOM_CAPSULE_ID);
    let dir = child.dir.path();
    let state = state_with_discovery(dir).await;
    let service = state.collaboration_discovery_service.clone().unwrap();
    let mut steps = Steps::new("direct messages: parent-signed device, child Runtime");
    // No Profile is stored yet: the loader `direct_authority` calls answers
    // `Ok(None)`, which that function turns into its authority refusal
    // (gateway_room.rs:285-291). Anything else fails this step.
    let launched = load_configured_contact_authority_for_context(dir, &child.ctx, Some(&service))
        .map(|found| found.map(|_| "a contact authority"));
    steps.step_where(
        "as launched, no Profile yet: the direct authority is none",
        launched,
        Option::is_none,
    );
    // Seeded state: a child cannot produce it today; the test writes it.
    let profile = seed_parent_profile(&child);
    let by_route = direct_authority_for(dir, &child.ctx, &service);
    let by_route = steps.step("seeded Profile: direct authority for the context", by_route);
    // The route's constructor, handed the seeded Profile. It answers because
    // the seed lists this Runtime's own device on the Profile; the
    // constructor refuses a Profile that does not
    // (collaboration_contact_store.rs:914-916).
    let authority = by_route.or_else(|| {
        let built = configured_contact_authority_from_profile(dir, &child.ctx, &service, profile);
        steps.step("seeded Profile handed to the route's constructor", built)
    });
    match authority {
        Some(authority) => {
            let now = crate::auth::now_ts();
            let listed = register_and_read(&mut steps, &service, &child.ctx, &authority, now);
            // This person has no contact, so the list read back is empty.
            if let Some(listed) = listed {
                steps.check("no conversation is listed", listed.is_empty(), &listed);
            }
        }
        None => steps.not_reached("register and read", "no contact authority"),
    }
    steps.finish();
}

#[tokio::test]
async fn r8c_control_direct_messages_register_read_and_send_under_the_stored_persons_root() {
    let control = control(CHAT_ROOM_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let profile = load_profile_for_authority(dir, &control.authority);
    let (identity_key, _) = elastos_identity::load_or_create_did(dir).unwrap();
    let local_key = SigningKey::from_bytes(&identity_key.to_bytes());
    let peer = crate::collaboration_discovery_runtime::tests::direct_gateway_peer_fixture(
        dir,
        &control.authority.principal_id,
        &control.root,
        &local_key,
        &profile,
    )
    .await;
    let mut steps = Steps::new("direct messages: stored person (control)");
    let authority = direct_authority_for(dir, &control.ctx, &peer.service);
    match steps.step("direct authority for the context", authority) {
        Some(authority) => {
            let (service, ctx, now) = (&peer.service, &control.ctx, crate::auth::now_ts());
            let listed = register_and_read(&mut steps, service, ctx, &authority, now);
            let conversation = peer.conversation_id.as_str();
            let found = listed
                .as_ref()
                .is_some_and(|ids| ids.iter().any(|id| id == conversation));
            steps.check(
                "the accepted contact's conversation is listed",
                found,
                &listed,
            );
            send_and_read_back(&mut steps, service, ctx, &authority, conversation, now).await;
        }
        None => steps.not_reached("register, read and send", "no contact authority"),
    }
    steps.only_under(
        dir,
        &control.root,
        ".AppData/ElastOS/Chat/direct-messages.json",
    );
    steps.finish();
}
