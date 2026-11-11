//! Family 4. Entries: `home_room_profile_card_projection_for_context`
//! (gateway_home_system.rs:6545) and `trusted_chat_room_profile_authority`
//! (gateway_room.rs:1340), which the Chat room session routes call.

use super::*;

fn card_steps(steps: &mut Steps, dir: &std::path::Path, ctx: &HomeLaunchTokenContext, did: &str) {
    let card = home_room_profile_card_projection_for_context(dir, ctx)
        .and_then(|card| card.ok_or_else(|| anyhow::anyhow!("no card: Profile required")));
    let card = steps.step("room profile card for the context", card);
    let card_did = card.map(|card| card.profile_id);
    steps.check(
        "the card names this Profile",
        card_did.as_deref() == Some(did),
        &card_did,
    );
    let trusted = trusted_chat_room_profile_authority(dir, ctx)
        .map(|profile| profile.document().profile_did.clone());
    let trusted = steps.step("room trusted profile authority", trusted);
    steps.check(
        "the authority is this Profile",
        trusted.as_deref() == Some(did),
        &trusted,
    );
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_room_card_and_authority_read_the_parent_roots_profile() {
    let child = child(CHAT_ROOM_CAPSULE_ID);
    let dir = child.dir.path();
    let mut steps = Steps::new("room profile card: parent-signed device, child Runtime");
    // No Profile is stored yet: the projection answers `Ok(None)`, which its
    // callers turn into their Profile-required answer
    // (gateway_home_system.rs:6557-6558). Anything else fails this step.
    let empty = home_room_profile_card_projection_for_context(dir, &child.ctx)
        .map(|card| card.map(|card| card.profile_id));
    steps.step_where(
        "as launched, no Profile yet: the room profile card is none",
        empty,
        Option::is_none,
    );
    let seeded = seed_parent_profile(&child);
    let did = seeded.document().profile_did.clone();
    card_steps(&mut steps, dir, &child.ctx, &did);
    steps.only_under(
        dir,
        &child.parent_root,
        ".AppData/ElastOS/Profile/profile-authority.json",
    );
    steps.finish();
}

#[test]
fn r8c_control_room_card_and_authority_read_the_stored_persons_profile() {
    let control = control(CHAT_ROOM_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let did = load_profile_for_authority(dir, &control.authority)
        .document()
        .profile_did
        .clone();
    let mut steps = Steps::new("room profile card: stored person (control)");
    card_steps(&mut steps, dir, &control.ctx, &did);
    steps.finish();
}
