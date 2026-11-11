//! Family 3. Entries: `request_community_presence`
//! (gateway_collaboration_presence.rs:310), `community_presence_state`
//! (line 299) and `answer_community_presence_request` (line 425), called by
//! `chat_room_community_presence_request` and the Inbox action route.

use super::*;
use crate::collaboration_presence_grant as grant;

const GRANT_FILE: &str = ".AppData/ElastOS/Home/community-presence.json";
/// What a presence request answers before a Profile is stored
/// (gateway_collaboration_presence.rs:287).
const PROFILE_REQUIRED: &str = "Create your Profile before choosing how Community shows you.";

fn presence_state(dir: &std::path::Path) -> GatewayState {
    let chat = crate::collaboration_product::test_chat_product_port(dir, "r8c", "community");
    let presence = crate::collaboration_presence::CollaborationPresenceProductPort::new(
        chat.test_core().clone(),
    )
    .unwrap()
    .with_presence_authority(grant::test_authority());
    let mut state = test_state(dir);
    state.collaboration_chat_product_port = Some(chat);
    state.collaboration_presence_product_port = Some(presence);
    state
}

async fn presence_steps(steps: &mut Steps, state: &GatewayState, ctx: &HomeLaunchTokenContext) {
    let asked = request_community_presence(state, ctx, true);
    steps.step(
        "request a presence grant (request_community_presence)",
        asked,
    );
    let read = community_presence_state(state, ctx);
    steps.check(
        "read presence state: requested",
        read == Some("requested"),
        &read,
    );
    let scope = state
        .collaboration_presence_product_port
        .as_ref()
        .unwrap()
        .presence_scope();
    // The stored-file functions the two calls above reach, with the same id.
    let id = ctx.principal_id();
    let direct = grant::state(&state.data_dir, id, &scope);
    steps.step_where(
        "presence grant file read (presence_grant::state): requested",
        direct,
        |mode| *mode == Some("requested"),
    );
    let open = grant::open_request_at(&state.data_dir, id, &scope);
    let open = steps.step("open presence request (open_request_at)", open);
    let open = open.flatten();
    // The request made above must be open: the answer and the last read
    // below run only on an open request.
    steps.check("the presence request is open", open.is_some(), &open);
    let Some(at) = open else {
        steps.not_reached("set the presence grant", "no open request to answer");
        return;
    };
    let action = format!("community-presence-always:{at}");
    let answered = answer_community_presence_request(state, ctx, &action)
        .await
        .unwrap_or_else(|| Err(anyhow::anyhow!("{action} is not a presence action")));
    steps.step("set the presence grant (answer: always)", answered);
    let read = community_presence_state(state, ctx);
    steps.check("read presence state: always", read == Some("always"), &read);
}

#[tokio::test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
async fn r8c_child_presence_request_and_grant_under_the_parent_root() {
    let child = child(CHAT_ROOM_CAPSULE_ID);
    let dir = child.dir.path();
    let state = presence_state(dir);
    let mut steps = Steps::new("presence: parent-signed device, child Runtime");
    // No Profile is stored yet: the request must answer exactly that one is
    // required. Any other answer, or a granted request, fails this step.
    let asked = request_community_presence(&state, &child.ctx, true);
    let asked = asked.map_err(|error| format!("{error:#}"));
    steps.check(
        "as launched, no Profile yet: the request answers that a Profile is required",
        asked == Err(PROFILE_REQUIRED.to_string()),
        &asked,
    );
    seed_parent_profile(&child);
    presence_steps(&mut steps, &state, &child.ctx).await;
    steps.only_under(dir, &child.parent_root, GRANT_FILE);
    steps.finish();
}

#[tokio::test]
async fn r8c_control_presence_request_and_grant_under_the_stored_persons_root() {
    let control = control(CHAT_ROOM_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let state = presence_state(dir);
    let mut steps = Steps::new("presence: stored person (control)");
    presence_steps(&mut steps, &state, &control.ctx).await;
    steps.only_under(dir, &control.root, GRANT_FILE);
    steps.finish();
}
