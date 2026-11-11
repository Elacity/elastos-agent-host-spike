//! Row 8, recovery readiness. Entry: `recovery_readiness_for_context`
//! (gateway_home_system.rs:6482), which the identity summary and the Home
//! event stream call.

use super::*;

fn readiness(dir: &std::path::Path, ctx: &HomeLaunchTokenContext) -> Value {
    serde_json::to_value(recovery_readiness_for_context(dir, ctx)).unwrap()
}

#[test]
fn r8d_child_recovery_readiness_is_answered_for_the_passkey_person() {
    let person = passkey_person(PEOPLE_CAPSULE_ID);
    // The child looks up the protection record in its own auth state
    // (auth_gateway.rs:1390-1393) and finds none.
    let on_child = readiness(person.child.path(), &person.ctx);
    assert_eq!(on_child["status"], "setup_required");
    assert_eq!(on_child["reason"], "recovery_kit_missing");
    // The parent stores the protection record for the same person and root.
    let stored =
        crate::auth::load_principal_root_protection(person.parent.path(), PERSON, ROOT).unwrap();
    assert!(stored.is_some(), "the parent stores the protection");
    assert_no_bytes_on_child(&person);
}
