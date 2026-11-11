//! Row 2, Profile load. Entries: `load_profile_authority_for_context`
//! (gateway_home_system.rs:1222) and `load_gateway_identity_summary_for_context`
//! (gateway_home_runtime.rs:400), which `home_summary` and `people_summary`
//! call. The update row sits beside the private `update_profile_for_context`.

use super::*;

fn identity_summary(dir: &std::path::Path, ctx: &HomeLaunchTokenContext) -> Value {
    serde_json::to_value(load_gateway_identity_summary_for_context(dir, ctx).unwrap()).unwrap()
}

#[test]
fn r8d_child_profile_load_reads_the_passkey_persons_profile() {
    let person = passkey_person(PEOPLE_CAPSULE_ID);
    let child = person.child.path();
    // The child answers "no Profile": the bundle path under its own data
    // directory holds no file, so the load returns before any storage call.
    let loaded = load_profile_authority_for_context(child, &person.ctx).unwrap();
    assert!(loaded.is_none(), "the child reads no Profile");
    let summary = identity_summary(child, &person.ctx);
    assert_eq!(summary["profile_readiness"]["status"], "setup_required");
    assert_eq!(summary["recovery_readiness"]["status"], "setup_required");
    assert_eq!(
        summary["recovery_readiness"]["reason"],
        "recovery_kit_missing"
    );
    assert_eq!(summary["profile"], Value::Null);
    // The setup name is read from the child's own auth state, which has no
    // record for the person, so none is offered.
    assert_eq!(summary["profile_setup_display_name"], Value::Null);
    // The same two calls on the parent's data directory, same context.
    let parent = person.parent.path();
    let on_parent = load_profile_authority_for_context(parent, &person.ctx).unwrap();
    let name = on_parent.map(|profile| profile.document().display_name.clone());
    assert_eq!(name.as_deref(), Some("Parent Person"));
    let summary = identity_summary(parent, &person.ctx);
    assert_eq!(summary["profile_readiness"]["status"], "ready");
    assert_eq!(summary["profile"]["display_name"], "Parent Person");
    assert_no_bytes_on_child(&person);
}
