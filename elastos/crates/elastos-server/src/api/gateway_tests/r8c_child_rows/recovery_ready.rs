//! Family 5. Entry: `recovery_readiness_for_context`
//! (gateway_home_system.rs:6482), which the identity summary and the Home
//! event stream call. It answers `unavailable` when its read is refused.

use super::*;

fn readiness(dir: &std::path::Path, ctx: &HomeLaunchTokenContext) -> Result<String, String> {
    let summary = serde_json::to_value(recovery_readiness_for_context(dir, ctx)).unwrap();
    let status = summary["status"].as_str().unwrap_or_default().to_string();
    if status == "unavailable" {
        return Err("recovery readiness is unavailable".to_string());
    }
    Ok(format!("{status} {}", summary["reason"]))
}

#[test]
#[ignore = "R8c: refused for a parent-signed device on a child Runtime"]
fn r8c_child_recovery_readiness_is_answered_for_the_parent_device() {
    let child = child(PEOPLE_CAPSULE_ID);
    let dir = child.dir.path();
    let mut steps = Steps::new("recovery readiness: parent-signed device, child Runtime");
    let launched = readiness(dir, &child.ctx);
    steps.step("as launched: recovery readiness", launched);
    // With protection and a Profile under the root, readiness reads the Profile.
    seed_parent_profile(&child);
    let seeded = readiness(dir, &child.ctx);
    steps.step("protected root with a Profile: recovery readiness", seeded);
    steps.finish();
}

#[test]
fn r8c_control_recovery_readiness_is_answered_for_the_stored_person() {
    let control = control(PEOPLE_CAPSULE_ID);
    let dir = control.dir.path();
    provision_signed_profile(dir, &control.authority, "Stored Person");
    let mut steps = Steps::new("recovery readiness: stored person (control)");
    let answered = readiness(dir, &control.ctx);
    steps.step(
        "protected root with a Profile: recovery readiness",
        answered,
    );
    steps.finish();
}
