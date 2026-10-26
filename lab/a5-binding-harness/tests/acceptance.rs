//! The acceptance rows, one per A5 binding check. Each row is ignored with
//! exactly the RA-* capabilities its check still needs. Forced with
//! `--ignored`, a row reports BLOCKED, SKIPPED or FAIL by failing; it passes
//! only after its journey ran against a live operator.

use a5_binding_harness::capability::Check;
use a5_binding_harness::{acceptance, Grade};

fn row(check: Check) {
    match acceptance(check) {
        Grade::Pass(evidence) => println!("ACCEPTED {}: {evidence}", check.test_name()),
        other => panic!(
            "{} {}: {}",
            other.label(),
            check.test_name(),
            other.detail()
        ),
    }
}

#[test]
#[ignore = "blocked: RA-1; RA-5; RA-6"]
fn acceptance_a5_identity_grant_used_by_bound_agent() {
    row(Check::IdentityUse);
}

#[test]
#[ignore = "blocked: RA-1; RA-5; RA-6"]
fn acceptance_a5_identity_grant_replayed_by_other_agent() {
    row(Check::IdentityReplay);
}

#[test]
#[ignore = "blocked: RA-1; RA-6"]
fn acceptance_a5_session_grant_used_in_bound_session() {
    row(Check::SessionUse);
}

#[test]
#[ignore = "blocked: RA-1; RA-2; RA-6"]
fn acceptance_a5_session_grant_reused_after_session_end() {
    row(Check::SessionEnded);
}

#[test]
#[ignore = "blocked: RA-1; RA-6"]
fn acceptance_a5_instance_grant_used_by_bound_instance() {
    row(Check::InstanceUse);
}

#[test]
#[ignore = "blocked: RA-1; RA-6"]
fn acceptance_a5_instance_grant_used_by_sibling() {
    row(Check::InstanceSibling);
}

#[test]
#[ignore = "blocked: RA-1; RA-3; RA-5; RA-6"]
fn acceptance_a5_owned_storage_grant_used_on_bound_root() {
    row(Check::StorageUse);
}

#[test]
#[ignore = "blocked: RA-1; RA-3; RA-5; RA-6"]
fn acceptance_a5_owned_storage_grant_pointed_at_other_root() {
    row(Check::StorageOtherRoot);
}

#[test]
#[ignore = "blocked: RA-6"]
fn acceptance_a5_public_storage_read_is_not_binding() {
    row(Check::PublicNotBinding);
}
