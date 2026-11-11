//! Family 5. Entry: `recovery_readiness_for_context`
//! (gateway_home_system.rs:6482), which the identity summary and the Home
//! event stream call. It answers `unavailable` when its read is refused
//! (line 6499).
//!
//! The answers these rows expect come from
//! `principal_root_recovery_readiness_for_verified_principal`
//! (auth_gateway.rs:1385-1407):
//! - no protection record for the person and root: `setup_required` with
//!   `recovery_kit_missing` (lines 1390-1394);
//! - a verified kit that does not cover the Profile under the root:
//!   `setup_required` with `recovery_kit_outdated` (lines 1402-1406, the
//!   cover check at 1364-1369). The test protection both fixtures store is
//!   verified and names no Profile (auth.rs:12969, 12963), so once the
//!   Profile under the root is read this is the answer for both.

use super::*;

/// The readiness answer as `status reason`, with `-` for no reason.
fn readiness(dir: &std::path::Path, ctx: &HomeLaunchTokenContext) -> String {
    let summary = serde_json::to_value(recovery_readiness_for_context(dir, ctx)).unwrap();
    let field = |name: &str| summary[name].as_str().unwrap_or("-").to_string();
    format!("{} {}", field("status"), field("reason"))
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_recovery_readiness_with_a_profile_under_the_protected_parent_root() {
    let child = child(PEOPLE_CAPSULE_ID);
    let dir = child.dir.path();
    let mut steps = Steps::new("recovery readiness: parent-signed device, child Runtime");
    // The child stores no protection record for this person and root.
    let launched = readiness(dir, &child.ctx);
    steps.check(
        "as launched: readiness is setup_required, recovery_kit_missing",
        launched == "setup_required recovery_kit_missing",
        &launched,
    );
    // With protection and a Profile under the root, readiness reads the Profile.
    // Seeded state: a child cannot produce it today; the test writes it.
    seed_parent_profile(&child);
    let seeded = readiness(dir, &child.ctx);
    steps.check(
        "protected root with a Profile: readiness is setup_required, recovery_kit_outdated",
        seeded == "setup_required recovery_kit_outdated",
        &seeded,
    );
    steps.finish();
}

#[test]
fn r8c_control_recovery_readiness_is_answered_for_the_stored_person() {
    let control = control(PEOPLE_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let mut steps = Steps::new("recovery readiness: stored person (control)");
    let answered = readiness(dir, &control.ctx);
    steps.check(
        "protected root with a Profile: readiness is setup_required, recovery_kit_outdated",
        answered == "setup_required recovery_kit_outdated",
        &answered,
    );
    steps.finish();
}
