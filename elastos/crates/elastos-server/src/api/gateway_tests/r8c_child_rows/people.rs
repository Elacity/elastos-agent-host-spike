//! Family 2. Entries: `load_configured_contact_authority_for_context`
//! (gateway_home_system.rs:1183) and `send_profile_contact_request_response`
//! (line 854), which `people_contact_request_create` (line 789) calls.

use super::*;

const PEOPLE_DIR: &str = ".AppData/ElastOS/People/";

async fn contact_steps(
    steps: &mut Steps,
    state: &GatewayState,
    ctx: &HomeLaunchTokenContext,
    authority: Option<ConfiguredContactAuthority>,
    root: &str,
) {
    let Some(authority) = authority else {
        steps.not_reached("contact store read and add", "no contact authority");
        return;
    };
    let read = authority.store.read_only_snapshot().map(|_| ());
    steps.step("load the contact store (read_only_snapshot)", read);
    let service = state.collaboration_discovery_service.clone().unwrap();
    let recipient = crate::crypto::encode_signing_key_did(&SigningKey::from_bytes(
        &generate_keypair().0.to_bytes(),
    ));
    let names = std::collections::HashMap::new();
    let response =
        send_profile_contact_request_response(&service, state, &names, ctx, &authority, &recipient)
            .await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&body).into_owned();
    let added = if status == StatusCode::OK {
        Ok(())
    } else {
        Err(format!("{status} {body}"))
    };
    steps.step(
        "add a contact (send_profile_contact_request_response)",
        added,
    );
    let prefix = format!("{}/{PEOPLE_DIR}", root.trim_start_matches("localhost://"));
    let files = files_under_roots(&state.data_dir);
    let landed = files
        .iter()
        .any(|file| file.starts_with(&prefix) && file.ends_with(".json"));
    steps.check("contact bytes are under this root", landed, &files);
    // The store write `people_discovery_update` reaches, for its exact error.
    let direct = authority
        .store
        .set_discovery_enabled(true, crate::auth::now_ts());
    steps.step("contact store write (set_discovery_enabled)", direct);
}

#[tokio::test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
async fn r8c_child_contacts_load_and_add_under_the_parent_root() {
    let child = child(PEOPLE_CAPSULE_ID);
    let dir = child.dir.path();
    let state = state_with_discovery(dir).await;
    let service = state.collaboration_discovery_service.clone().unwrap();
    let mut steps = Steps::new("contacts: parent-signed device, child Runtime");
    let load = || {
        load_configured_contact_authority_for_context(dir, &child.ctx, Some(&service))
            .and_then(|found| found.ok_or_else(|| anyhow::anyhow!("none: Profile required")))
    };
    steps.step("as launched: contact authority for the context", load());
    let profile = seed_parent_profile(&child);
    let by_route = steps.step("seeded Profile: contact authority for the context", load());
    // The same constructor the route uses, handed the seeded Profile, so the
    // contact store's own storage calls are reached too.
    let authority = by_route.or_else(|| {
        let built = configured_contact_authority_from_profile(dir, &child.ctx, &service, profile);
        steps.step("seeded Profile handed to the route's constructor", built)
    });
    contact_steps(
        &mut steps,
        &state,
        &child.ctx,
        authority,
        &child.parent_root,
    )
    .await;
    let strays: Vec<_> = files_under_roots(dir)
        .into_iter()
        .filter(|file| !file.starts_with(child.parent_root.trim_start_matches("localhost://")))
        .collect();
    steps.check(
        "nothing is under any other root",
        strays.is_empty(),
        &strays,
    );
    steps.finish();
}

#[tokio::test]
async fn r8c_control_contacts_load_and_add_under_the_stored_persons_root() {
    let control = control(PEOPLE_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let state = state_with_discovery(dir).await;
    let service = state.collaboration_discovery_service.clone().unwrap();
    let mut steps = Steps::new("contacts: stored person (control)");
    let authority =
        load_configured_contact_authority_for_context(dir, &control.ctx, Some(&service))
            .and_then(|found| found.ok_or_else(|| anyhow::anyhow!("none: Profile required")));
    let authority = steps.step("contact authority for the context", authority);
    contact_steps(&mut steps, &state, &control.ctx, authority, &control.root).await;
    steps.finish();
}
