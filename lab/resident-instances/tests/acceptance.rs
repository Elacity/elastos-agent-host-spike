//! The acceptance rows, one per M1 check. Each row is ignored with exactly the
//! Runtime capabilities its check still needs. Forced with `--ignored`, a row
//! reports BLOCKED, SKIPPED or FAIL by failing; it passes only after its
//! journey ran against a live operator.

use resident_instances::capability::Check;
use resident_instances::{acceptance, Grade};

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
#[ignore = "blocked: RI-1; RI-2; RI-3; RI-4"]
fn acceptance_a3_two_resident_instances_in_one_runtime() {
    row(Check::A3);
}

#[test]
#[ignore = "blocked: RI-1; RI-2; RI-3; RI-4; RI-7"]
fn acceptance_a6_instance_grant_does_not_authorise_sibling() {
    row(Check::A6);
}

#[test]
#[ignore = "blocked: RI-1; RI-2; RI-3; RI-4; RI-5"]
fn acceptance_a10_cancel_one_instance_sibling_unaffected() {
    row(Check::A10);
}

#[test]
#[ignore = "blocked: RI-1; RI-2; RI-3; RI-4; RI-5; RI-6"]
fn acceptance_a11_failed_instance_request_settled_by_runtime() {
    row(Check::A11);
}

#[test]
#[ignore = "blocked: RI-1; RI-2; RI-3; RI-4; RI-7"]
fn acceptance_a12_stopped_instances_leave_nothing_behind() {
    row(Check::A12);
}
