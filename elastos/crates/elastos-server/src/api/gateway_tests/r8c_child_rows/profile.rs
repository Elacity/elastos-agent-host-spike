//! Family 1, load. Entry: `load_profile_authority_for_context`
//! (gateway_home_system.rs:1222) and `load_gateway_identity_summary_for_context`
//! (gateway_home_runtime.rs:381), which `home_summary` and `people_summary`
//! call. The update rows sit beside the private `update_profile_for_context`.

use super::*;

fn load_steps(
    steps: &mut Steps,
    dir: &std::path::Path,
    ctx: &HomeLaunchTokenContext,
    expected_did: &str,
) {
    let loaded = steps.step(
        "load the stored Profile (load_profile_authority_for_context)",
        load_profile_authority_for_context(dir, ctx),
    );
    let did = loaded
        .flatten()
        .map(|profile| profile.document().profile_did.clone());
    steps.check(
        "the Profile returned is the one under this root",
        did.as_deref() == Some(expected_did),
        &did,
    );
    let summary = load_gateway_identity_summary_for_context(dir, ctx)
        .map(|summary| serde_json::to_value(summary).unwrap());
    if let Some(summary) = steps.step("identity summary", summary) {
        let status = summary["profile_readiness"]["status"].clone();
        steps.check(
            "identity summary says Profile ready",
            status == "ready",
            &status,
        );
    }
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_profile_load_reads_the_profile_under_the_parent_root() {
    let child = child(PEOPLE_CAPSULE_ID);
    let dir = child.dir.path();
    let mut steps = Steps::new("profile load: parent-signed device, child Runtime");
    // No Profile is stored yet: the load answers `Ok(None)`.
    let empty = load_profile_authority_for_context(dir, &child.ctx)
        .map(|found| found.map(|profile| profile.document().profile_did.clone()));
    steps.step_where(
        "as launched, no Profile yet: the load answers none",
        empty,
        Option::is_none,
    );
    // Seeded state: a child cannot produce it today; the test writes it.
    let seeded = seed_parent_profile(&child);
    let expected = seeded.document().profile_did.clone();
    load_steps(&mut steps, dir, &child.ctx, &expected);
    steps.only_under(
        dir,
        &child.parent_root,
        ".AppData/ElastOS/Profile/profile-authority.json",
    );
    assert!(!files_under_roots(dir)
        .iter()
        .any(|file| file.contains(child.child_root.trim_start_matches("localhost://"))));
    steps.finish();
}

#[test]
fn r8c_control_profile_load_reads_the_stored_persons_profile() {
    let control = control(PEOPLE_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let expected = load_profile_for_authority(dir, &control.authority)
        .document()
        .profile_did
        .clone();
    let mut steps = Steps::new("profile load: stored person (control)");
    load_steps(&mut steps, dir, &control.ctx, &expected);
    steps.only_under(
        dir,
        &control.root,
        ".AppData/ElastOS/Profile/profile-authority.json",
    );
    steps.finish();
}
