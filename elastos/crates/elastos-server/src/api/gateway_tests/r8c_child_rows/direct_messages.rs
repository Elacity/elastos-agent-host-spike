//! Family 6. `direct_authority` (gateway_room.rs:271) builds the contact
//! authority for the context; the three Chat direct-message routes then call
//! `register_configured_contact_sync_for_context`, `conversation_summaries`,
//! `message_summaries` and `send_text_authorized` (lines 313, 359, 411).

use super::*;
use crate::collaboration_direct_messages::{DirectSendAuthority, DirectSendIntent};

const NO_CONTACT: &str =
    "no accepted contact can be arranged: the contact store refuses this person's writes";

fn direct_authority_for(
    dir: &std::path::Path,
    ctx: &HomeLaunchTokenContext,
    service: &crate::collaboration_discovery_runtime::CollaborationDiscoveryService,
) -> anyhow::Result<ConfiguredContactAuthority> {
    load_configured_contact_authority_for_context(dir, ctx, Some(service))
        .and_then(|found| found.ok_or_else(|| anyhow::anyhow!("none: Profile required")))
}

async fn direct_steps(
    steps: &mut Steps,
    service: &crate::collaboration_discovery_runtime::CollaborationDiscoveryService,
    ctx: &HomeLaunchTokenContext,
    authority: Option<ConfiguredContactAuthority>,
    conversation: Option<&str>,
) {
    let Some(authority) = authority else {
        steps.not_reached("register, read and send", "no contact authority");
        return;
    };
    let now = crate::auth::now_ts();
    let registered = register_configured_contact_sync_for_context(service, ctx, &authority, now);
    steps.step("register the context for direct messages", registered);
    let direct = service.direct_message_service();
    let listed = direct.conversation_summaries(authority.store.as_ref());
    let listed = steps.step("read conversations (conversation_summaries)", listed);
    let Some(conversation) = conversation else {
        steps.not_reached("send one message", NO_CONTACT);
        return;
    };
    let found = listed.is_some_and(|list| list.iter().any(|c| c.conversation_id == conversation));
    steps.check(
        "the accepted contact's conversation is listed",
        found,
        &conversation,
    );
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
    steps.step("send one message (send_text_authorized)", sent.map(|_| ()));
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
    let authority = steps.step("direct authority for the context", authority);
    let conversation = Some(peer.conversation_id.as_str());
    direct_steps(
        &mut steps,
        &peer.service,
        &control.ctx,
        authority,
        conversation,
    )
    .await;
    steps.only_under(
        dir,
        &control.root,
        ".AppData/ElastOS/Chat/direct-messages.json",
    );
    steps.finish();
}
